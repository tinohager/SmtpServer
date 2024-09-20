using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SmtpServer
{
    internal sealed class SmtpSessionManager
    {
        readonly SmtpServer _smtpServer;
        readonly ConcurrentDictionary<Guid, SmtpSessionHandle> _sessions = new ConcurrentDictionary<Guid, SmtpSessionHandle>();
        //readonly object _sessionsLock = new object();
        //readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

        internal SmtpSessionManager(SmtpServer smtpServer)
        {
            _smtpServer = smtpServer;
        }

        internal void Run(SmtpSessionContext sessionContext, CancellationToken cancellationToken)
        {
            var handle = new SmtpSessionHandle(new SmtpSession(sessionContext), sessionContext);

            Add(handle);
            var smtpSessionTask = RunAsync(handle, cancellationToken).ContinueWith(task =>
            {
                Remove(handle);
            });

            handle.CompletionTask = smtpSessionTask;
        }

        async Task RunAsync(SmtpSessionHandle handle, CancellationToken cancellationToken)
        {
            using var sessionReadTimeoutCancellationTokenSource = new CancellationTokenSource(handle.SessionContext.EndpointDefinition.SessionTimeout);
            using var linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, sessionReadTimeoutCancellationTokenSource.Token);

            try
            {
                await UpgradeAsync(handle, linkedTokenSource.Token);

                linkedTokenSource.Token.ThrowIfCancellationRequested();

                _smtpServer.OnSessionCreated(new SessionEventArgs(handle.SessionContext));

                await handle.Session.RunAsync(linkedTokenSource.Token);

                _smtpServer.OnSessionCompleted(new SessionEventArgs(handle.SessionContext));
            }
            catch (OperationCanceledException)
            {
                _smtpServer.OnSessionCancelled(new SessionEventArgs(handle.SessionContext));
            }
            catch (Exception ex)
            {
                _smtpServer.OnSessionFaulted(new SessionFaultedEventArgs(handle.SessionContext, ex));
            }
            finally
            {
                await handle.SessionContext.Pipe.Input.CompleteAsync();
                
                handle.SessionContext.Pipe.Dispose();
            }
        }

        async Task UpgradeAsync(SmtpSessionHandle handle, CancellationToken cancellationToken)
        {
            var endpoint = handle.SessionContext.EndpointDefinition;

            if (endpoint.IsSecure && endpoint.CertificateFactory != null)
            {
                var serverCertificate = endpoint.CertificateFactory.GetServerCertificate(handle.SessionContext);

                await handle.SessionContext.Pipe.UpgradeAsync(serverCertificate, endpoint.SupportedSslProtocols, cancellationToken).ConfigureAwait(false);
            }
        }

        internal Task WaitAsync()
        {
            IReadOnlyList<Task> tasks;

            tasks = _sessions.Values.Select(session => session.CompletionTask).ToList();
            
            return Task.WhenAll(tasks);
        }

        void Add(SmtpSessionHandle handle)
        {
            _sessions.TryAdd(handle.SessionId, handle);
        }

        void Remove(SmtpSessionHandle handle)
        {
            _sessions.TryRemove(handle.SessionId, out _);
        }

        class SmtpSessionHandle
        {
            public SmtpSessionHandle(SmtpSession session, SmtpSessionContext sessionContext)
            {
                SessionId = Guid.NewGuid();

                Session = session;
                SessionContext = sessionContext;
            }

            public override bool Equals(object obj)
            {
                if (obj is SmtpSessionHandle other)
                {
                    return SessionId == other.SessionId;
                }

                return false;
            }

            public override int GetHashCode()
            {
                return SessionId.GetHashCode();
            }

            public Guid SessionId { get; }

            public SmtpSession Session { get; }
            
            public SmtpSessionContext SessionContext { get; }

            public Task CompletionTask { get; set; }
        }
    }
}
