//
// Created by glebf on 9/25/19.
//

#ifndef PRODUCT12_CCAffinityThread_H
#define PRODUCT12_CCAffinityThread_H

#include <thread>
#include <vector>
#include <iostream>
#include <set>
#include <errno.h>

///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

//! A thin wrapper above std::thread and pthread to support CPU affinity.
class CAffinityThread
{
public:

    //! Type of a set of CPUs assigned to a thread
    using CpuSet = std::set<uint16_t>;

    //! Type of list of spawned threads (see spawnMultipleThreads())
    using ListOfThread = std::vector<std::unique_ptr<CAffinityThread>>;

    //! Construct a thread object that represents a new joinable thread of execution.
    //! The new thread of execution calls fn passing args as arguments (using decay copies of its lvalue or rvalue references).
    //! The completion of this construction synchronizes with the beginning of the invocation of this copy of fn.
    //! The constructor sets the CPU affinity mask of the thread thread to the CPU set pointed to by cpuset.
    //!
    //! \tparam Fn      - type of thread execution function - deduced automatically
    //! \tparam Args    - type of thread parameters - deduced automatically
    //! \param cpuSet   - affinity mask of the thread. If the set is empty or nullptr then affinity is not used.
    //! \param fn       - A pointer to function, pointer to member, or any kind of move-constructible function object
    //!                   (i.e., an object whose class defines operator(), including closures and function objects).
    //!                   The return value (if any) is ignored.
    //! \param args     - Arguments passed to the call to fn (if any). Their types shall be move-constructible.
    //!                   If fn is a member pointer, the first argument shall be an object for which that member
    //!                   is defined (or a reference, or a pointer to it).
    template <class Fn, class... Args>
    explicit CAffinityThread (   CpuSet              cpuSet,
                                Fn&&                fn,
                                Args&&...           args ) :
            m_thread( [cpuSet, fn, args...]()
                      {
                          // Set the required CPU affinity
                          if ( cpuSet.size() )
                          {
                              //! Use this wrapper over cpu_set_t to prevent notes from compiler c++14 and higher
                              struct Set : public cpu_set_t
                              {
                                  Set(CpuSet cpuSet) { CPU_ZERO(this); for ( auto cpu : cpuSet ) CPU_SET( cpu, this); }
                              };
                              Set set(cpuSet);
                              int res = sched_setaffinity( 0, sizeof(set), &set );
                          }
                          fn(args...);
                      } ) {}


    //! Destroys the thread object.
    //! If the thread is joinable when destroyed, join() is called.
    ~CAffinityThread()
    {
        // Join the thread to make sure it is done
        try { join(); }
        catch( std::invalid_argument )  {}
    }


    //!  The function returns when the thread execution has completed.
    //!  This synchronizes the moment this function returns with the completion of all the operations in the thread: This blocks the execution of the thread that calls this function until the function called on construction returns (if it hasn't yet).
    //!  After a call to this function, the thread object becomes non-joinable and can be destroyed safely.
    void join() { m_thread.join(); }

    //! Stop the thread forcefully
    void forceStop( void ) { if (joinable()) pthread_cancel(m_thread.native_handle()); }


    //! Check if joinable
    //!
    //! \return whether the thread object is joinable.
    bool joinable() const noexcept { return m_thread.joinable(); };


    //! Spawn a thread for each available CPU in a set
    //! If CPU set is empty then only one thread is spawned
    //!
    //! \tparam Fn      - type of thread execution function - deduced automatically
    //! \tparam Args    - type of thread parameters - deduced automatically
    //! \param cpuSet   - affinity mask of the thread. If the set is empty or nullptr then affinity is not used.
    //! \param fn       - A pointer to function, pointer to member, or any kind of move-constructible function object
    //!                   (i.e., an object whose class defines operator(), including closures and function objects).
    //!                   The return value (if any) is ignored.
    //! \param args     - Arguments passed to the call to fn (if any). Their types shall be move-constructible.
    //!                   If fn is a member pointer, the first argument shall be an object for which that member
    //!                   is defined (or a reference, or a pointer to it).
    //! \return a list of created threads
    template <class Fn, class... Args>
    static ListOfThread spawnMultipleThreads( CpuSet       cpuSet,
                                              Fn&&         fn,
                                              Args&&...    args )
    {
        // Start with an empty list of threads
        ListOfThread threadList;

        // Set the required CPU affinity
        if ( !cpuSet.size() ) // Single CPU
        {
            threadList.push_back( std::unique_ptr<CAffinityThread>(new CAffinityThread(cpuSet, fn, args... )) );
        }
        else // Multiple CPUs
        {
            // Look for CPUs in the set and spawn a thread for each one of them
            for ( auto cpu : cpuSet )
            {
                threadList.push_back( std::unique_ptr<CAffinityThread>(new CAffinityThread( {cpu}, fn, args... )) );
            }
        }

        return std::move(threadList);
    }

private:

    //! Attached thread object
    std::thread m_thread;
};


#endif //PRODUCT12_CCAffinityThread_H
