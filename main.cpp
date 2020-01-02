#include <iostream>
#include <vector>
#include <zconf.h>
#include "external_classifier.h"
#include "domain_tree.h"

void classifier_cb( std::string domain, MultiConnectionType service_type )
{
    std::cout << "Service type of " << domain << " is " << int(service_type) << std::endl;
}

int main() {
    std::cout << "Hello, World!" << std::endl;

    /*
    ExternalClassifier classifier( "NqIJfPmTmrqa0e8gHbEn:IgAbGoTEYPVMfdLScrLa" );
    classifier.register_classification_callback( classifier_cb );
    classifier.add_classification_request( "callofduty.com" );
    while(1)
    {
        sleep(10);
    }
    return 0;
     */

    DomainTree domain_tree("db.json", "NqIJfPmTmrqa0e8gHbEn:IgAbGoTEYPVMfdLScrLa" );

    struct Packet
    {
        std::string domain;
        uint16_t    port;
        ProtocolType protocol_type;
        MultiConnectionType service_type;
    };

    std::vector<Packet> packets =
    {
            { "callofduty.com", 100, ProtocolType::TCP, MultiConnectionType::small }
            /*
            { "www.youtube.com", 100, ProtocolType::TCP, MultiConnectionType::small },
            { "content-storage-download.googleapis.com", 100, ProtocolType::UDP, MultiConnectionType::small },
            { "123.456.789.12", 200,  ProtocolType::UDP, MultiConnectionType::small },
            { "", 43, ProtocolType::UDP, MultiConnectionType::small },
            { "123.456.789.12", 1234, ProtocolType::UDP, MultiConnectionType::small },
             */
//       "www.youtube.com",
//       "googlevideo.com",
//       "blabla.com"
    };

    bool more;
    do
    {
        more = false;
        for (auto& p : packets)
        {
            if ((p.service_type == MultiConnectionType::small) || (p.service_type == MultiConnectionType::quiering))
            {
                p.service_type = domain_tree.match_domain(p.domain, p.port, p.protocol_type, p.service_type);
                std::cout << "Category of " << p.domain << " port " << p.port <<
                          " over " << (p.protocol_type == ProtocolType::UDP ? "UDP" : "TCP") << " is " <<
                          int(p.service_type) << std::endl;
                more = true;
            }
        }

        sleep(1);
    }
    while(more);

    return 0;
}
