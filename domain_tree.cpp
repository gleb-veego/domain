//
// Created by glebf on 12/24/19.
//

#include "domain_tree.h"
#include <fstream>
#include <iostream>
#include <arpa/inet.h>

using namespace json11;

/////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Read database from a file to RAM
DomainTree::DomainTree( const std::string& db_filename, const std::string& external_serever_secret_key )
{
    if ( !external_serever_secret_key.empty() )
    {
        external_classifier_ptr_ = std::make_unique<ExternalClassifier>(external_serever_secret_key);
        external_classifier_ptr_->register_classification_callback(
           [this](const std::string& domain_name, MultiConnectionType service_type)
               { on_external_classifier_reply(domain_name, service_type); } );
    }

    std::string parse_error;
    std::cout << "DomainDb::DomainDb reading and parsing json" << std::endl;
    auto json = Json::parse( read_db_file(db_filename), parse_error );
    std::cout << "DomainDb::DomainDb reading and parsing done" << std::endl;

    if ( !fill(json) )
    {
        std::cout << "database error: " << parse_error << std::endl;
    }
    std::cout << "DomainDb::DomainDb filling database done" << std::endl;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Find a domain in the tree using inexact match: uses minimum number of trailing name tokens
MultiConnectionType DomainTree::match_domain( Domain domain_name, uint16_t port, ProtocolType protocol_type,
                                              MultiConnectionType current_service_type ) const
{
    // If a request to classify this domain has been issued then keep waiting
    if ( external_classifier_ptr_ && external_classifier_ptr_->is_request_pending(domain_name) )
    {
        return MultiConnectionType::quiering;
    }

    MultiConnectionType category = kUnclassified;
    Domain domain_name_org = domain_name;

    std::lock_guard<std::mutex> lock(database_mtx_);

    if ( !domain_name.empty() && is_ip_address(domain_name) ) // Exact search for IP address
    {
        category = find_domain_exact(domain_name, port, protocol_type);
    }
    else while ( !domain_name.empty() && (category == kUnclassified) ) // Inexact search for general domain
    {
        category = find_domain_exact(domain_name, port, protocol_type);
        remove_token( &domain_name );
    }

    if ( category == kUnclassified ) // Try to find the port in entries with empty domain
    {
        category = find_domain_exact("", port, protocol_type);
    }

    if ( (category == kUnclassified)   &&
         external_classifier_ptr_      &&
         (current_service_type != MultiConnectionType::quiering) ) // Try to find the domain on external server
    {
        external_classifier_ptr_->add_classification_request(domain_name_org);
        category = MultiConnectionType::quiering;
    }

    return category;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Find a domain in the tree using exact match and get the service type for the given protocol and port
MultiConnectionType DomainTree::find_domain_exact( const Domain& domain_name, uint16_t port, ProtocolType protocol_type ) const
{
    MultiConnectionType service_type = kUnclassified;

    auto port_list = select_ports_table( domain_name, protocol_type );
    if ( port_list != nullptr )
    {
        for ( const auto& port_range : *port_list )
        {
            if ( port_range.in_range(port) && (port_range.category !=kUnclassified) )
            {
                service_type = port_range.category;
                break;
            }
        }
    }

    return service_type;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Convert the category string to connection type
MultiConnectionType DomainTree::category_to_type( const Category& category )
{
    MultiConnectionType type = kUnclassified;
    if ( category == "streaming" ) type = MultiConnectionType::streaming_video;
    else if ( category == "downloading or streaming" ) type = MultiConnectionType::streaming_video;
    else if ( category == "live_streaming" ) type = MultiConnectionType::live_streaming_udp;
    else if ( category == "browsing" ) type = MultiConnectionType::browsing;
    else if ( category == "gaming" ) type = MultiConnectionType::gaming;

    return type;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Select port_table_tcp_ or port_table_udp_ of a domain for a given protocol type
DomainTree::ClassifiedDomain::PortList* DomainTree::select_ports_table( const Domain& domain_name,  ProtocolType protocol ) const
{
    auto domain_entry = domain_table_.find(domain_name);
    if ( domain_entry == domain_table_.end() ) return nullptr;

    std::list<PortRange>* ports_table;
    switch( protocol )
    {
        case ProtocolType::UDP:
            ports_table = const_cast<ClassifiedDomain::PortList*>(&domain_entry->second.port_table_udp);
            break;
        case ProtocolType::TCP:
            ports_table = const_cast<ClassifiedDomain::PortList*>(&domain_entry->second.port_table_tcp);
            break;
        default:
            ports_table = nullptr;
            break;
    }

    return ports_table;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Fill database with domains and ports and their categories
bool DomainTree::fill( const Json& domain_json )
{
    if ( !domain_json.is_object() ) return false;
    const auto& service_json = domain_json.object_items();

    // Each entry in service_json is collection of domains that provide a certain service: gaming, streaming, etc...
    bool result = true;
    for ( auto service_it = service_json.cbegin(); (service_it!=service_json.cend()) && result; ++service_it )
    {
        result = parse_service_json( service_it->second, category_to_type(service_it->first) );
    }

    // On error remove all entries
    if ( !result ) domain_table_.clear();

    return result;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Parse json definition of one service type
bool DomainTree::parse_service_json( const Json& service_json, MultiConnectionType service_type )
{
    if ( service_type == kUnclassified ) return false;
    if ( !service_json.is_array() ) return false;
    const auto& domain_json = service_json.array_items();
    std::cout << "Parsing service type " << int(service_type) << std::endl;

    // Each entry of domain_json is a descriptor for a single domain: its' name and port ranges
    bool result = true;
    for ( auto domain_it = domain_json.cbegin(); (domain_it!=domain_json.cend()) && result; ++domain_it )
    {
        result = parse_domain_json( *domain_it, service_type );
    }

    return result;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Parse a single domain json entry
bool DomainTree::parse_domain_json( const Json& ports_json, MultiConnectionType service_type )
{
    std::cout << "Parsing doman " << ports_json.dump() << std::endl;

    // The json here is expected to be an array of 3 entries: domain name, TCP ports, UDP ports
    if ( !ports_json.is_array() ) return false;
    const auto& protocol_items = ports_json.array_items();
    auto num_of_items = protocol_items.size();
    if ((num_of_items!=1) && (num_of_items!=3)) return false;
    const auto& domain_name_json = protocol_items[0];
    if ( !domain_name_json.is_string() ) return false;
    const auto& domain_name = domain_name_json.string_value();

    bool result = true;
    if ( num_of_items == 1 ) // ports not specified
    {
        if ( domain_name.empty() ) return false;
        domain_table_[domain_name] = ClassifiedDomain{service_type}; // Full port range for UDP and TCP
    }
    else // ports are specified
    {
        // Create a domain entry if it does not exist yet
        if ( domain_table_.count(domain_name) == 0 )
        {
            domain_table_[domain_name] = ClassifiedDomain{};
        }

        // This lambda is used to parse port ranges of a given protocol.
        auto parse_ports_range_lambda = [&](int range_idx, ProtocolType protocol_type )->bool
        { return parse_protocol_ports_range_json(
                protocol_items[1+range_idx], domain_name, protocol_type, service_type ); };

        // Parse port ranges for TCP and for UDP
        result =  parse_ports_range_lambda( 0, ProtocolType::TCP ) &&
                  parse_ports_range_lambda( 1, ProtocolType::UDP );
    }

    return result;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Parse port ranges json for a given protocol
bool DomainTree::parse_protocol_ports_range_json( const Json&           port_ranges_json,
                                                  const Domain&         domain_name,
                                                  ProtocolType          protocol_type,
                                                  MultiConnectionType   service_type )
{
    bool result = true;

    // port_ranges_json is expected to be an array of ranges.
    if ( !port_ranges_json.is_array() ) return false;
    const auto& port_ranges_items = port_ranges_json.array_items();

    for ( const auto& port_range_json : port_ranges_items )
    {
        result = result && parse_protocol_ports_json(domain_name, protocol_type, port_range_json, service_type );
    }

    return result;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Fill database with parameters for a given set of ports, providing a certain service type (stream, gaming, etc...)
bool DomainTree::parse_protocol_ports_json( const Domain&       domain_name,
                                            ProtocolType        protocol_type,
                                            const json11::Json& ports_json,
                                            MultiConnectionType service_type )
{
    if ( !ports_json.is_array() ) return false;
    const auto& port_items = ports_json.array_items();
    PortRange port_range(service_type); // by default use full range, i.e 0-65535
    if ( !port_items.empty() )
    {
        if ( (port_items.size() != 2) || !port_items[0].is_number() || !port_items[1].is_number() ) return false;
        port_range.first_port = static_cast<uint16_t>(port_items[0].number_value());
        port_range.last_port  = static_cast<uint16_t>(port_items[1].number_value());
        if ( port_range.first_port > port_range.last_port ) return false;
    }

    auto port_list = select_ports_table( domain_name, protocol_type );
    port_list->push_back( port_range );

    return true;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Read database from a file to string
std::string DomainTree::read_db_file( const std::string& db_filename )
{
    std::string str;
    std::ifstream ifs(db_filename);
    std::getline(ifs, str, (char)ifs.eof() );

    return str;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Calback routine provided to external classifier. Invoked on completion of a quiery
void DomainTree::on_external_classifier_reply( const std::string& domain_name, MultiConnectionType service_type )
{
    if ( service_type != kUnclassified )
    {
        std::lock_guard<std::mutex> lock(database_mtx_);
        domain_table_[domain_name] = ClassifiedDomain(service_type);
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Check whether a string is an IP address
[[nodiscard]] bool DomainTree::is_ip_address( const std::string str )
{
    struct sockaddr_in sa;
    return (inet_pton(AF_INET, str.c_str(), &(sa.sin_addr)) != 0);
}
