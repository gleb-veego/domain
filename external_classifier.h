//
// Created by glebf on 12/30/19.
//

#ifndef DOMAINDB_EXTERNAL_CLASSIFIER_H
#define DOMAINDB_EXTERNAL_CLASSIFIER_H

#include "Defines.h"
#include "Utils/CAffinityThread.h"
#include "Tools/json11.hpp"
#include <curl/curl.h>
#include <unordered_set>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! External classifier uses a service on external server to
//! attempt classification of a domain.
class ExternalClassifier
{
public: // types and members

    static const auto kUnclassified = MultiConnectionType::unclassified;

    //! Type of the callback function.
    //! Provides the service type for a domain or kUnclassified if could not classify.
    using ClassificationCallback = std::function<void( const std::string& domain_name, MultiConnectionType service_type )>;

public: // methods

    //! Construct an instance
    //!
    //! \param secret_key  - user secret key in the form 'james:bond' to access the server
    //! \param cpu_set     - set of CPU cores that can be used for processing
    explicit ExternalClassifier( const std::string& secret_key, const CAffinityThread::CpuSet& cpu_set={} );

    //! Terminate the object
    ~ExternalClassifier();

    //! Register a callback function that will be invoked after a classification request gets processed
    //!
    //! \param classification_callback - the callback function - will be called when the request is processed
    void register_classification_callback( ClassificationCallback classification_callback );

    //! Add a request to to resolve service type of a given domain
    //!
    //! \param domain_name                   - domain for which the request is issued
    void add_classification_request( const std::string& domain_name );

    //! Check if a request for a domain is pending
    //!
    //! \param domain_name - domain for which the request is issued
    [[nodiscard]] bool is_request_pending( const std::string& domain_name ) const;

private: // types and members

    //! Callback function that will be invoked after a classification request gets processed
    ClassificationCallback classification_callback_ = nullptr;

    //! Mutex for request queue
    mutable std::mutex request_mtx_;

    //! Set of classification requests awaiting processing
    std::unordered_set<std::string> pending_classification_requests;

    //! The execution task of the classifier requests
    std::unique_ptr<CAffinityThread> classifier_task_handler_ = nullptr;

    //! Termination signal for pinger thread
    std::atomic_bool terminate_request_ = ATOMIC_FLAG_INIT;

    //! CURL handle, used to access Fingerbank over HTTPS
    CURL* curl_ = nullptr;

    //! String for constructing reply from fingrbank
    std::string server_reply_;

private: // methods

    //! Curl callback for incoming data from classification server
    //!
    //! \param ptr          - the incoming data
    //! \param size         - always 1
    //! \param nmemb        - size of data
    //! \param userdata     - the calling context
    //! \return             - size of processed data
    static size_t classification_reply_handler( char *ptr, size_t size, size_t nmemb, void *userdata );

    //! Curl callback for incoming data from classification server within context
    //!
    //! \param ptr          - the incoming data
    //! \param nmemb        - size of data
    //! \return             - size of processed data
    size_t in_context_classification_reply_handler( char *ptr, size_t nmemb );

    //! Call function for the execution task of classification requests
    void classification_requests_processing_task();

    //! Convert reply from server to service type.
    //!
    //! \param server_reply - reply from the server
    //! \return corresponding service type
    static MultiConnectionType server_reply_to_service_type( const std::string& server_reply );

    //! Get category with the best score in an array of categories
    //!
    //! \param categories_array - array of categories from server
    //! \return service type of a category with the highest score or unclassified if no good fit is found
    static MultiConnectionType get_best_category_fit( const json11::Json::array& categories_array );

    //! Convert category type reported by server to service type.
    //!
    //! \param category_type - category type received from the server
    //! \return corresponding service type
    static MultiConnectionType category_type_to_service_type( const std::string& category_type );
};


#endif //DOMAINDB_EXTERNAL_CLASSIFIER_H
