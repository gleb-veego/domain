//
// Created by glebf on 12/24/19.
//

#include "domain_tree.h"
#include <fstream>
#include <iostream>

using namespace json11;

/////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Read database from a file to RAM
DomainTree::DomainTree( const std::string& db_filename )
{
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
MultiConnectionType DomainTree::match_domain( Domain domain_name, uint16_t port, ProtocolType protocol_type ) const
{
    MultiConnectionType category = kUnclassified;

    if ( !domain_name.empty() && std::isdigit(domain_name[0]) ) // Exact search for IP address
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
DomainTree::DomainEntry::PortList* DomainTree::select_ports_table( const Domain& domain_name,  ProtocolType protocol ) const
{
    auto domain_entry = domain_table_.find(domain_name);
    if ( domain_entry == domain_table_.end() ) return nullptr;

    std::list<PortRange>* ports_table;
    switch( protocol )
    {
        case ProtocolType::UDP:
            ports_table = const_cast<DomainEntry::PortList*>(&domain_entry->second.port_table_udp);
            break;
        case ProtocolType::TCP:
            ports_table = const_cast<DomainEntry::PortList*>(&domain_entry->second.port_table_tcp);
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

    bool result = true;
    for ( auto service_it = service_json.cbegin(); (service_it!=service_json.cend()) && result; ++service_it )
    {
        result = parse_service_json( service_it->second, category_to_type(service_it->first) );
    }

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
    if ( !ports_json.is_array() ) return false;
    const auto& protocol_items = ports_json.array_items();
    auto num_of_items = protocol_items.size();
    if ( (num_of_items!=1) && (num_of_items!=2) ) return false;
    const auto& domain_name_json = protocol_items[0];
    if ( !domain_name_json.is_string() ) return false;

    return parse_port_json( domain_name_json.string_value(),
                              (num_of_items == 1) ? nullptr : &protocol_items[1],
                              service_type );
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Parse port json array
bool DomainTree::parse_port_json( const Domain& domain_name, const Json* ports_json, MultiConnectionType service_type )
{
    bool result = true;

    bool ports_empty = (ports_json == nullptr);

    if ( !ports_empty ) // Not form (6) - see parse_domain_json above
    {
        if ( !ports_json->is_array() ) return false;
        const auto& ports_items = ports_json->array_items();
        ports_empty = ports_items.empty(); // Form (4)

        if ( !ports_empty ) // Not form (4)
        {
            if ( ports_items.size() != 2 ) return false;
            const auto& tcp_ports_json = ports_items[0];
            const auto& udp_ports_json = ports_items[1];
            if ( !tcp_ports_json.is_array() || !udp_ports_json.is_array() ) return false;
            const auto& udp_ports = udp_ports_json.array_items();
            const auto& tcp_ports = tcp_ports_json.array_items();
            ports_empty = (tcp_ports.empty() && udp_ports.empty()); // Form (5)

            if ( !ports_empty ) // Forms (1), (2) or (3)
            {
                if (domain_table_.count(domain_name) == 0) domain_table_.emplace(domain_name, DomainEntry{});
                result = parse_protocol_ports_json(domain_name, ProtocolType::TCP, tcp_ports, service_type) &&
                         parse_protocol_ports_json(domain_name, ProtocolType::UDP, udp_ports, service_type);
            }
        }
    }

    if ( ports_empty ) // Forms (4) or (5) or (6)
    {
        PortRange full_range(service_type);
        const auto& domain_it = domain_table_.find( domain_name );
        if ( domain_it != domain_table_.end() ) result = false;
        else domain_table_.emplace( domain_name, DomainEntry{&full_range, &full_range} );
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
    PortRange port_range(kUnclassified);
    if ( !port_items.empty() )
    {
        if ( (port_items.size() != 2) || !port_items[0].is_number() || !port_items[1].is_number() ) return false;
        port_range = PortRange{  static_cast<uint16_t>(port_items[0].number_value()),
                                 static_cast<uint16_t>(port_items[1].number_value()),
                                 service_type };
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
