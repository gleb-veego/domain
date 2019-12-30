//
// Created by glebf on 12/23/19.
//

#ifndef DOMAINDB_DOMAIN_TREE_H
#define DOMAINDB_DOMAIN_TREE_H

#include"Defines.h"
#include "Tools/json11.hpp"
#include <memory>
#include <unordered_map>
#include <list>
#include <iostream>

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Reads service information from a data file in json format and provides access to it.
//! The data file has the following format:
//! { "service_type" : service domains, ... }
//! Each domain will follow one of these forms:
//! (1) ["domain_name", [[tcp_ports_range],[udp_ports_range]]]    - domain and udp and tcp ports
//! (2) ["domain_name", [[tcp_ports_range],[]]]                   - domain and tcp ports
//! (3) ["domain_name", [[],[udp_ports_range]]]                   - domain and udp ports
//! (4) ["domain_name", []]                                       - domain without ports
//! (5) ["domain_name", [[],[]]]                                  - domain without ports
//! (6) ["domain_name"]                                           - domain without ports
class DomainTree
{
public:

    using Domain = std::string;

    static const auto kUnclassified = MultiConnectionType::unclassified;

public:

    //! Read database from a file to RAM
    //!
    //! \param db_filename  - path and name of the database file
    //! \throws
    explicit DomainTree( const std::string& db_filename );

    //! Find a domain in the tree using inexact match: uses minimum number of trailing name tokens
    //! to get a valid category value. If an IP address is provided as domain name - leading character is numeric -
    //! then exact match is used, i.e. tokens are not removed.
    //!
    //! \param domain     -  domain name to seek
    //! \param port       -  communication port to seek
    //! \protocol         - type of communication protocol
    //! \return domain category or kUnclassified if domain not found
    MultiConnectionType match_domain( Domain domain, uint16_t port, ProtocolType protocol ) const;

private:

    using Category = std::string;
    using Token = std::string;

    static const char kDelimiter = '.';

    struct PortRange
    {
        uint16_t                first_port;
        uint16_t                last_port;
        MultiConnectionType     category;

        PortRange(MultiConnectionType service_type) :
            first_port(0), last_port(std::numeric_limits<uint16_t>::max()), category(service_type) {}

        PortRange( uint16_t first, uint16_t last, MultiConnectionType service_type) :
                first_port(first), last_port(last), category(service_type) {}

        bool in_range( uint16_t port ) const { return ((port >= first_port) && (port <= last_port)); }
    };

    struct DomainEntry
    {
        using PortList = std::list<PortRange>;
        PortList port_table_tcp;
        PortList port_table_udp;

        DomainEntry() = default;
        explicit DomainEntry(const PortRange* port_tcp, const PortRange* port_udp)
        {
            if ( port_tcp ) port_table_tcp.push_back(*port_tcp);
            if ( port_udp ) port_table_udp.push_back(*port_udp);
        }
    };

    std::unordered_map<Domain, DomainEntry> domain_table_;

private:

    //! Find a domain in the tree using exact match and get the service type for the given protocol and port
    //!
    //! \param domain     -  domain name to seek
    //! \param port       -  communication port to seek
    //! \protocol         - type of communication protocol
    //! \return domain category or kUnclassified if domain not found
    MultiConnectionType find_domain_exact( const Domain& domain, uint16_t port, ProtocolType protocol ) const;

    //! Remove the leading token from a string, ie www.google.com -> google.com -> com
    static void remove_token( Domain* domain )
    {
        auto pos = domain->find(kDelimiter);
        if (pos != std::string::npos) *domain = domain->substr(pos+1);
        else domain->clear();
    }

    //! Convert the category string to connection type
    //!
    //! \param category - the category string
    //! \return the corresponding connection type
    static MultiConnectionType category_to_type( const Category& category );

    //! Select port_table_tcp_ or port_table_udp_ of a domain for a given protocol type
    //!
    //! \param domain_name   - name of the domain
    //! \param protocol_type - UDP or TCP protocol
    //! \return pointer to selected table or nullptr if illegal protocol
    DomainEntry::PortList* select_ports_table( const Domain& domain_name,  ProtocolType protocol_type ) const;

    //! Fill database with domains and ports and their categories
    //!
    //! \param json   - description of database in json format
    //! \return true if parameters are valid, false if not
    bool fill( const json11::Json& json );

    //! Parse json definition of one service type
    //!
    //! \param service_json - descriptor of a service
    //! \param service_type - the service type
    //! \return true on success, false on failure
    bool parse_service_json( const json11::Json& service_json, MultiConnectionType service_type );

    //! Parse a single domain json entry
    //!
    //! \param domain_json  - descriptor of a domain
    //! \param service_type - the service type
    //! \return true on success, false on failure
    bool parse_domain_json( const json11::Json& domain_json, MultiConnectionType service_type );

    //! Parse port json array
    //!
    //! \param domain_name  - name of the domain
    //! \param ports_json   - descriptor of ports or nullptr if no ports
    //! \param service_type - the service type
    //! \return true on success, false on failure
    bool parse_port_json( const Domain& domain_name, const json11::Json* ports_json, MultiConnectionType service_type );

    //! Fill database with parameters for a given set of ports, providing a certain service type (stream, gaming, etc...)
    //!
    //! \param domain_name  - name of the domain
    //! \param protocol_type- protocol type: UDP or TCP
    //! \param ports_json   - descriptor of all ports for a given domain
    //! \param service_type - the service type
    //! \return true on success, false on failure
    bool parse_protocol_ports_json( const Domain&       domain_name,
                                    ProtocolType        protocol_type,
                                    const json11::Json& ports_json,
                                    MultiConnectionType service_type );

    //! Read database from a file to string
    //!
    //! \param db_filename  - path and name of the database file
    //! \param return the content of the file in a string
    //! \throws
    static std::string read_db_file( const std::string& db_filename );
};


#endif //DOMAINDB_DOMAIN_TREE_H
