//
// Created by glebf on 12/30/19.
//

#include "external_classifier.h"
#include "Tools/base64.h"
#include "Tools/json11.hpp"
#include <memory>
#include <utility>
#include <zconf.h>

using namespace json11;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Construct an instance
ExternalClassifier::ExternalClassifier( const std::string& secret_key, const CAffinityThread::CpuSet& cpu_set )
{
    // Create CURL handle and configure it
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_ = curl_easy_init();
    if ( curl_ )
    {
        curl_easy_setopt(curl_, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, this );
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, classification_reply_handler );
//        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, curl_slist_append(nullptr, "Content-Type: application/json"));
        curl_easy_setopt(curl_, CURLOPT_USERAGENT, "curl/7.58.0");
        curl_easy_setopt(curl_, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl_, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl_, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl_, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl_, CURLOPT_USERPWD, secret_key.c_str());
    }

    // STart thread for processing classification requests
    classifier_task_handler_ =
            std::make_unique<CAffinityThread>( cpu_set, [this](){ classification_requests_processing_task(); } );
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Terminate the object
ExternalClassifier::~ExternalClassifier()
{
    terminate_request_ = true;
    classifier_task_handler_.reset(nullptr);
    if ( curl_ )
    {
        curl_easy_cleanup(curl_);
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Register a callback function that will be invoked after a classification request gets processed
void ExternalClassifier::register_classification_callback( ClassificationCallback classification_callback )
{
    std::lock_guard<std::mutex> lock(request_mtx_);
    classification_callback_ = std::move(classification_callback);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Add a request to to resolve service type of a given domain
void ExternalClassifier::add_classification_request( const std::string& domain_name )
{
    std::lock_guard<std::mutex> lock(request_mtx_);
    pending_classification_requests.emplace( domain_name );
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Curl callback for incoming data from classification server
size_t ExternalClassifier::classification_reply_handler( char *ptr, size_t, size_t nmemb, void *userdata )
{
    // Call the corresponding function in provided context
    return (static_cast<ExternalClassifier*>(userdata))->in_context_classification_reply_handler( ptr, nmemb );
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Curl callback for incoming data from classification server within context
size_t ExternalClassifier::in_context_classification_reply_handler( char *ptr, size_t nmemb )
{
    // Response must not exceed this size
    static const size_t MAX_RESPONSE_SIZE = 2048;

    // Limit the size of the reply
    auto replySize = server_reply_.length();
    if ( (replySize + nmemb) > MAX_RESPONSE_SIZE )
    {
        nmemb = (replySize < MAX_RESPONSE_SIZE) ? (MAX_RESPONSE_SIZE-replySize) : 0;
    }

    // Get the reply
    server_reply_.append( ptr, nmemb );

    return nmemb;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Call function for the execution task of classification requests
void ExternalClassifier::classification_requests_processing_task()
{
    // Repeat until termination is requested
    while( !terminate_request_ )
    {
        // Wait for data in the job queue
        sleep(1);

        // Process all pending jobs
        while ( !terminate_request_ && !pending_classification_requests.empty() )
        {
            // Get one pending domain request
            std::unique_lock<std::mutex> lock(request_mtx_);
            auto const& request_it = pending_classification_requests.begin();
            lock.unlock();
            auto base64_encoded_domain_name = base64_encode( request_it->c_str() );

            std::string url = "https://api.webshrinker.com/categories/v3/" + base64_encoded_domain_name;
            curl_easy_setopt(curl_, CURLOPT_URL,  url.c_str());

            // Perform the request and get the reply in server_reply_
            server_reply_.clear();
            auto curl_code = curl_easy_perform(curl_);

            // Process the reply and pass the result to the user
            if ( (curl_code==CURLE_OK) && (classification_callback_ != nullptr) )
            {
                classification_callback_( *request_it, server_reply_to_service_type(server_reply_) );
            }

            lock.lock();
            pending_classification_requests.erase(request_it);
            lock.unlock();
        }
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Convert reply from server to service type.
MultiConnectionType ExternalClassifier::server_reply_to_service_type( const std::string& server_reply )
{
    MultiConnectionType service_type = kUnclassified;

    // Try to convert the reply to json
    std::string json_error;
    auto json = Json::parse( server_reply, json_error );

    if ( json.is_object() )
    {
        const auto& data_items = json.object_items();
        const auto data_it = data_items.find("data");
        if ( (data_it != data_items.end()) && (data_it->second.is_array()) )
        {
            const auto& data_array = data_it->second.array_items();
            if ( (data_array.size() == 1) && (data_array.at(0).is_object()) )
            {
                const auto& categories = data_array[0]["categories"];
                if ( categories.is_array() )
                {
                    service_type = get_best_category_fit( categories.array_items() );
                }
            }
        }
    }

    return service_type;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Get category with the best score in an array of categories
MultiConnectionType ExternalClassifier::get_best_category_fit( const Json::array& categories_array )
{
    auto best_score = "0";
    auto best_is_confident = false;
    auto best_service_type = kUnclassified;

    for ( const auto& category : categories_array )
    {
        if ( category.is_object() )
        {
            const auto& category_items = category.object_items();
            const auto confident_it = category_items.find("confident");
            const auto score_it = category_items.find("score");
            const auto id_it = category_items.find("id");

            if (    (confident_it!=category_items.end()) && (confident_it->second.is_bool())       &&
                    (score_it!=category_items.end())     && (score_it->second.is_string())         &&
                    (id_it!=category_items.end())        && (id_it->second.is_string()) )
            {
                auto confident = confident_it->second.bool_value();
                auto score = score_it->second.string_value();
                auto id = id_it->second.string_value();

                if ( (confident || !best_is_confident)  &&  (score > best_score) )
                {
                    auto service_type = category_type_to_service_type(id);
                    if ( service_type != kUnclassified )
                    {
                        best_service_type = service_type;
                    }
                }
            }
        }
    }

    return best_service_type;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//! Convert category type reported by server tor service type.
MultiConnectionType ExternalClassifier::category_type_to_service_type( const std::string& category_type )
{
    static const std::unordered_map<std::string, MultiConnectionType> relevant_categories =
    {
        { "IAB25-WS2",  MultiConnectionType::streaming_video },
        { "IAB9-30",    MultiConnectionType::gaming },
        { "IAB1-7",     MultiConnectionType::streaming_video },
        { "IAB25-WS1",  MultiConnectionType::streaming_video },
    };

    const auto relevant_category_it = relevant_categories.find(category_type);
    return ( (relevant_category_it != relevant_categories.end())
                    ? relevant_category_it->second
                    : kUnclassified );
}
