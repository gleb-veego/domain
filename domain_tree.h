//
// Created by glebf on 12/23/19.
//

#ifndef DOMAINDB_DOMAIN_TREE_H
#define DOMAINDB_DOMAIN_TREE_H

#include"Defines.h"
#include "external_classifier.h"
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
//! Each domain will have one of the following forms:
//! (1) - ["domain_name", [tcp_ports_range],[udp_ports_range]]
//! (2) - ["domain_name"] - the name of the domain must not be empty
//! Each port range may contain zero or more pairs of first and last port value: [f1,l1], [f2,l2],...
//! If ranges are not specified - form (2) - a full range will be used
//! an example of a valid data file is: { "service_type":["domain_name", [[tcp1,tcp2],[tcp3,tcp4]], [[udp1,udp2],[udp3,udp4]]] }
class DomainTree
{
public:

    using Domain = std::string;

    static const auto kUnclassified = MultiConnectionType::unclassified;

public:

    //! Read database from a file to RAM
    //!
    //! \param db_filename                  - path and name of the database file
    //! \param external_serever_secret_key  - secret key used to access external server for classification of domains
    //! \throws
    explicit DomainTree( const std::string& db_filename, const std::string& external_serever_secret_key = "" );

    //! Find a domain in the tree using inexact match: uses minimum number of trailing name tokens
    //! to get a valid category value. If an IP address is provided as domain name - leading character is numeric -
    //! then exact match is used, i.e. tokens are not removed.
    //!
    //! \param domain_name          -  domain name to seek
    //! \param port                 -  communication port to seek
    //! \param protocol_type        - type of communication protocol
    //! \param current_service_type - last detected service type of the domain
    //! \return domain category or kUnclassified if domain not found
    MultiConnectionType match_domain( Domain domain_name, uint16_t port, ProtocolType protocol_type,
                                      MultiConnectionType current_service_type ) const;

private:

    using Category = std::string;
    using Token = std::string;

    //! Characters that separate tokens in a URL
    static const char kDelimiter = '.';

    //! Range of communication ports that correspond to a certain service type for a domain
    struct PortRange
    {
        uint16_t                first_port;
        uint16_t                last_port;
        MultiConnectionType     category;

        explicit PortRange( MultiConnectionType service_type,
                            uint16_t            first=0,
                            uint16_t            last=std::numeric_limits<uint16_t>::max() ) :
            first_port(first), last_port(last), category(service_type) {}

        [[nodiscard]] bool in_range( uint16_t port ) const { return ((port >= first_port) && (port <= last_port)); }
    };

    //! Descriptor of a classified domain
    struct ClassifiedDomain
    {
        using PortList = std::list<PortRange>;
        PortList port_table_tcp;
        PortList port_table_udp;

        ClassifiedDomain() = default;

        explicit  ClassifiedDomain( MultiConnectionType service_type ) :
                port_table_tcp{ PortRange(service_type) }, port_table_udp{PortRange(service_type)} {}
    };

    //! The internal database of classified domains
    std::unordered_map<Domain, ClassifiedDomain> domain_table_;

    //! An object used to quiery an external server if a domain could not be classified
    //! usinn the internal database.
    std::unique_ptr<ExternalClassifier> external_classifier_ptr_ = nullptr;

    //! Mutex for accessing database
    mutable std::mutex database_mtx_;

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
    ClassifiedDomain::PortList* select_ports_table( const Domain& domain_name,  ProtocolType protocol_type ) const;

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

    //! Parse port ranges json for a given protocol
    //!
    //! \param port_ranges_json  - list of port ranges for the given protocol
    //! \param domain_name       - name of the domain
    //! \param protocol_type     - protocol type: UDP or TCP
    //! \param service_type      - the service type
    //! \return true on success, false on failure
    bool parse_protocol_ports_range_json( const json11::Json&   port_ranges_json,
                                          const Domain&         domain_name,
                                          ProtocolType          protocol_type,
                                          MultiConnectionType   service_type );

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

    //! Calback routine provided to external classifier. Invoked on completion of a quiery
    //!
    //! \param domain_name  - name of the domain
    //! \param service_type - the service type detected by the external classifier
    void on_external_classifier_reply( const std::string& domain_name, MultiConnectionType service_type );

    //! Check whether a string is an IP address
    //!
    //! \param str - the input string
    //! \return true if str is IP address, false if not
    [[nodiscard]] static bool is_ip_address( const std::string str );
};


#endif //DOMAINDB_DOMAIN_TREE_H
