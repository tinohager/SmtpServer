using System;
using System.Collections.Generic;

namespace Nager.SmtpServerCore
{
    /// <summary>
    /// Smtp Server Options Builder
    /// </summary>
    public sealed class SmtpServerOptionsBuilder
    {
        readonly List<Action<SmtpServerOptions>> _setters = new List<Action<SmtpServerOptions>>();

        /// <summary>
        /// Builds the options that have been set and returns the built instance.
        /// </summary>
        /// <returns>The server options that have been set.</returns>
        public ISmtpServerOptions Build()
        {
            var serverOptions = new SmtpServerOptions
            {
                MaxMessageSizeOptions = new MaxMessageSizeOptions(),
                MaxConcurrentSessions = 100,
                Endpoints = new List<IEndpointDefinition>(),
                MaxRetryCount = 5,
                MaxRcptToCount = 10,
                MaxAuthenticationAttempts = 3,
                CommandWaitTimeout = TimeSpan.FromMinutes(5),
                CustomSmtpGreeting = null,
            };

            _setters.ForEach(setter => setter(serverOptions));

            return serverOptions;
        }

        /// <summary>
        /// Sets the server name.
        /// </summary>
        /// <param name="value">The name of the server.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder ServerName(string value)
        {
            _setters.Add(options => options.ServerName = value);

            return this;
        }

        /// <summary>
        /// Adds a definition for an endpoint to listen on.
        /// </summary>
        /// <param name="value">The endpoint to listen on.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder Endpoint(IEndpointDefinition value)
        {
            _setters.Add(options => options.Endpoints.Add(value));

            return this;
        }

        /// <summary>
        /// Adds a definition for an endpoint to listen on.
        /// </summary>
        /// <param name="configure">The endpoint to listen on.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder Endpoint(Action<EndpointDefinitionBuilder> configure)
        {
            var endpointDefinitionBuilder = new EndpointDefinitionBuilder();
            configure(endpointDefinitionBuilder);

            return Endpoint(endpointDefinitionBuilder.Build());
        }

        /// <summary>
        /// Adds an endpoint with the given port.
        /// </summary>
        /// <param name="ports">The port to add as the endpoint.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder Port(params int[] ports)
        {
            foreach (var port in ports)
            {
                Endpoint(new EndpointDefinitionBuilder().Port(port).Build());
            }

            return this;
        }

        /// <summary>
        /// Adds an endpoint with the given port.
        /// </summary>
        /// <param name="port">The port to add as the endpoint.</param>
        /// <param name="isSecure">Indicates whether the port is secure by default.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder Port(int port, bool isSecure)
        {
            Endpoint(new EndpointDefinitionBuilder().Port(port).IsSecure(isSecure).Build());

            return this;
        }

        /// <summary>
        /// Sets the maximum message size.
        /// </summary>
        /// <param name="length">The maximum message size to allow in bytes.</param>
        /// <param name="handling">The handling type.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder MaxMessageSize(int length, MaxMessageSizeHandling handling = MaxMessageSizeHandling.Ignore)
        {
            _setters.Add(options => options.MaxMessageSizeOptions = new MaxMessageSizeOptions(handling, length));

            return this;
        }

        /// <summary>
        /// Sets the maximum number of concurrent SMTP sessions.
        /// </summary>
        /// <param name="maxConcurrentSessions">The maximum number of concurrent sessions to allow.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder MaxConcurrentSessions(int maxConcurrentSessions)
        {
            _setters.Add(options => options.MaxConcurrentSessions = maxConcurrentSessions);

            return this;
        }

        /// <summary>
        /// Sets the maximum number of retries for a failed command.
        /// </summary>
        /// <param name="value">The maximum number of retries allowed for a failed command.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder MaxRetryCount(int value)
        {
            _setters.Add(options => options.MaxRetryCount = value);

            return this;
        }

        /// <summary>
        /// Sets the maximum number of recipients allowed for a single email message.
        /// </summary>
        /// <param name="value">The maximum number of recipients allowed for a single email message.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder MaxRcptToCount(int value)
        {
            _setters.Add(options => options.MaxRcptToCount = value);

            return this;
        }

        /// <summary>
        /// Sets the maximum number of authentication attempts.
        /// </summary>
        /// <param name="value">The maximum number of authentication attempts for a failed authentication.</param>
        /// <returns>A OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder MaxAuthenticationAttempts(int value)
        {
            _setters.Add(options => options.MaxAuthenticationAttempts = value);

            return this;
        }

        /// <summary>
        /// Sets the timeout used when waiting for a command from the client.
        /// </summary>
        /// <param name="value">The timeout used when waiting for a command from the client.</param>
        /// <returns>An OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder CommandWaitTimeout(TimeSpan value)
        {
            _setters.Add(options => options.CommandWaitTimeout = value);
            
            return this;
        }

        /// <summary>
        /// Sets the custom SMTP greeting message sent to the client upon connection,
        /// typically returned as the initial "220" response.
        /// </summary>
        /// <param name="smtpGreetingFunc">
        /// A delegate that returns the greeting message to send to the client,
        /// based on the <see cref="ISessionContext"/> (e.g., client IP, TLS state).
        /// Example: <c>sessionContext => $"220 {sessionContext.ServerOptions.ServerName} ESMTP ready"</c>
        /// </param>
        /// <returns>An OptionsBuilder to continue building on.</returns>
        public SmtpServerOptionsBuilder CustomSmtpGreeting(Func<ISessionContext, string> smtpGreetingFunc)
        {
            _setters.Add(options => options.CustomSmtpGreeting = smtpGreetingFunc);

            return this;
        }

        #region SmtpServerOptions

        class SmtpServerOptions : ISmtpServerOptions
        {
            /// <inheritdoc/>
            public IMaxMessageSizeOptions MaxMessageSizeOptions { get; set; }

            /// <inheritdoc/>
            public int MaxConcurrentSessions { get; set; }

            /// <inheritdoc/>
            public int MaxRetryCount { get; set; }

            /// <inheritdoc/>
            public int MaxRcptToCount { get; set; }

            /// <inheritdoc/>
            public int MaxAuthenticationAttempts { get; set; }

            /// <inheritdoc/>
            public string ServerName { get; set; }

            /// <inheritdoc/>
            internal List<IEndpointDefinition> Endpoints { get; set; }

            /// <inheritdoc/>
            IReadOnlyList<IEndpointDefinition> ISmtpServerOptions.Endpoints => Endpoints;

            /// <inheritdoc/>
            public TimeSpan CommandWaitTimeout { get; set; }

            /// <inheritdoc/>
            public Func<ISessionContext, string> CustomSmtpGreeting { get; set; }
        }

        #endregion
    }
}
