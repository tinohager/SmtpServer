using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Nager.SmtpServerCore.Mail;

namespace Nager.SmtpServerCore.Protocol
{
    public sealed class SmtpParser
    {
        private static readonly SmtpResponse UnrecognizedCommand = new(SmtpReplyCode.CommandNotImplemented, "Unrecognized command");

        private readonly ISmtpCommandFactory _smtpCommandFactory;

        public SmtpParser(ISmtpCommandFactory smtpCommandFactory)
        {
            _smtpCommandFactory = smtpCommandFactory;
        }

        public bool TryMake(ref ReadOnlySequence<byte> buffer, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            command = null;
            errorResponse = null;

            var reader = new SequenceReader<byte>(buffer);

            SkipWhitespace(ref reader);

            bool success = false;

            if (MatchVerb(ref reader, "EHLO"u8)) success = TryMakeEhlo(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "HELO"u8)) success = TryMakeHelo(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "MAIL"u8)) success = TryMakeMail(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "RCPT"u8)) success = TryMakeRcpt(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "DATA"u8)) success = TryMakeData(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "QUIT"u8)) success = TryMakeQuit(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "RSET"u8)) success = TryMakeRset(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "NOOP"u8)) success = TryMakeNoop(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "STARTTLS"u8)) success = TryMakeStartTls(ref reader, out command, out errorResponse);
            else if (MatchVerb(ref reader, "AUTH"u8)) success = TryMakeAuth(ref reader, out command, out errorResponse);
            else
            {
                errorResponse = UnrecognizedCommand;
                return false;
            }

            if (success)
            {
                // HIER: Puffer um die verarbeiteten Bytes nach vorne schieben!
                buffer = buffer.Slice(reader.Position);
            }

            return success;
        }

        internal static bool MatchVerb(ref SequenceReader<byte> reader, ReadOnlySpan<byte> verb)
        {
            if (reader.Remaining < verb.Length) return false;

            // Nutze stackalloc oder UnreadSpan ohne Array-Allokation
            Span<byte> temp = stackalloc byte[verb.Length];
            if (!reader.TryCopyTo(temp)) return false;

            // Nutze den eingebauten BCL-Optimierten Ascii-Vergleich
            if (!Ascii.EqualsIgnoreCase(temp, verb)) return false;

            if (reader.Remaining > verb.Length)
            {
                // Prüfen ob nach dem Verb ein Trennzeichen kommt
                var nextPosition = reader.Sequence.GetPosition(verb.Length, reader.Position);
                if (reader.Sequence.TryGet(ref nextPosition, out var memory) && memory.Length > 0)
                {
                    byte nextByte = memory.Span[0];
                    if (nextByte != (byte)' ' && nextByte != (byte)'\t' && nextByte != (byte)'\r' && nextByte != (byte)'\n')
                    {
                        return false;
                    }
                }
            }

            reader.Advance(verb.Length);
            return true;
        }

        internal static bool TrySkipPrefix(ref SequenceReader<byte> reader, ReadOnlySpan<byte> prefix)
        {
            if (reader.Remaining < prefix.Length) return false;

            Span<byte> temp = stackalloc byte[prefix.Length];
            if (reader.TryCopyTo(temp) && Ascii.EqualsIgnoreCase(temp, prefix))
            {
                reader.Advance(prefix.Length);
                return true;
            }

            return false;
        }

        internal static void SkipWhitespace(ref SequenceReader<byte> reader)
        {
            while (reader.TryPeek(out byte b) && (b == (byte)' ' || b == (byte)'\t'))
            {
                reader.Advance(1);
            }
        }

        internal bool TryMakeEhlo(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            command = null;
            errorResponse = null;

            SkipWhitespace(ref reader);

            var lineSequence = reader.Sequence.Slice(reader.Position);
            string domainOrAddress = ReadLineAsString(lineSequence).Trim('[', ']', ' ', '\r', '\n');

            if (string.IsNullOrWhiteSpace(domainOrAddress))
            {
                errorResponse = SmtpResponse.SyntaxError;
                return false;
            }

            command = _smtpCommandFactory.CreateEhlo(domainOrAddress);
            return true;
        }

        internal bool TryMakeHelo(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            command = null;
            errorResponse = null;

            SkipWhitespace(ref reader);

            var lineSequence = reader.Sequence.Slice(reader.Position);
            string domainOrAddress = ReadLineAsString(lineSequence).Trim('[', ']', ' ', '\r', '\n');

            if (!IsValidDomainOrHost(domainOrAddress))
            {
                errorResponse = SmtpResponse.SyntaxError;
                return false;
            }

            command = _smtpCommandFactory.CreateHelo(domainOrAddress);
            return true;
        }

        internal bool TryMakeMail(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            command = null;
            errorResponse = null;

            SkipWhitespace(ref reader);

            if (!TrySkipPrefix(ref reader, "FROM:"u8))
            {
                errorResponse = new SmtpResponse(SmtpReplyCode.SyntaxError, "missing the FROM:");
                return false;
            }

            SkipWhitespace(ref reader);

            if (!TryReadPath(ref reader, out var mailboxStr))
            {
                errorResponse = new SmtpResponse(SmtpReplyCode.SyntaxError);
                return false;
            }

            IMailbox mailbox = ParseMailbox(mailboxStr);
            var parameters = ParseParameters(ref reader);

            command = _smtpCommandFactory.CreateMail(mailbox, parameters);
            return true;
        }

        internal bool TryMakeRcpt(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            command = null;
            errorResponse = null;

            SkipWhitespace(ref reader);

            if (!TrySkipPrefix(ref reader, "TO:"u8))
            {
                errorResponse = new SmtpResponse(SmtpReplyCode.SyntaxError, "missing the TO:");
                return false;
            }

            SkipWhitespace(ref reader);

            if (!TryReadPath(ref reader, out var mailboxStr))
            {
                errorResponse = SmtpResponse.SyntaxError;
                return false;
            }

            if (!TryParseMailbox(mailboxStr, out var mailbox))
            {
                errorResponse = SmtpResponse.SyntaxError;
                return false;
            }

            if (!string.IsNullOrEmpty(mailbox.Host) && !IsValidDomainOrHost(mailbox.Host))
            {
                errorResponse = SmtpResponse.SyntaxError;
                return false;
            }

            command = _smtpCommandFactory.CreateRcpt(mailbox);
            return true;
        }

        private static bool TryParseMailbox(string mailboxStr, out IMailbox mailbox)
        {
            mailbox = null;

            if (string.IsNullOrEmpty(mailboxStr))
            {
                mailbox = Mailbox.Empty;
                return true;
            }

            int lastAt = mailboxStr.LastIndexOf('@');
            if (lastAt <= 0)
            {
                return false;
            }

            string user = mailboxStr.Substring(0, lastAt);
            string host = mailboxStr.Substring(lastAt + 1);

            bool isQuoted = user.StartsWith('"') && user.EndsWith('"') && user.Length >= 2;

            if (isQuoted)
            {
                user = user.Substring(1, user.Length - 2);
            }
            else
            {
                // Ohne Quotes darf der User-Teil kein '@' enthalten
                if (user.Contains('@'))
                {
                    return false;
                }
            }

            if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(user))
            {
                return false;
            }

            mailbox = new Mailbox(user, host);
            return true;
        }

        internal bool TryMakeQuit(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            errorResponse = null;
            command = _smtpCommandFactory.CreateQuit();
            return true;
        }

        internal bool TryMakeData(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            errorResponse = null;
            command = _smtpCommandFactory.CreateData();
            return true;
        }

        internal bool TryMakeNoop(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            errorResponse = null;
            command = _smtpCommandFactory.CreateNoop();
            return true;
        }

        internal bool TryMakeRset(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            errorResponse = null;
            command = _smtpCommandFactory.CreateRset();
            return true;
        }

        internal bool TryMakeStartTls(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            errorResponse = null;
            command = _smtpCommandFactory.CreateStartTls();
            return true;
        }

        internal bool TryMakeAuth(ref SequenceReader<byte> reader, out SmtpCommand command, out SmtpResponse errorResponse)
        {
            command = null;
            errorResponse = null;

            SkipWhitespace(ref reader);

            string line = ReadLineAsString(reader.Sequence.Slice(reader.Position)).Trim('\r', '\n', ' ');

            if (string.IsNullOrWhiteSpace(line))
            {
                errorResponse = SmtpResponse.SyntaxError;
                return false;
            }

            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);

            AuthenticationMethod? method = parts[0].ToUpperInvariant() switch
            {
                "PLAIN" => AuthenticationMethod.Plain,
                "LOGIN" => AuthenticationMethod.Login,
                _ => null
            };

            if (method == null)
            {
                errorResponse = SmtpResponse.SyntaxError;
                return false;
            }

            string parameter = parts.Length > 1 ? parts[1] : string.Empty;
            command = _smtpCommandFactory.CreateAuth(method.Value, parameter);
            return true;
        }

        internal static bool TryReadPath(ref SequenceReader<byte> reader, out string path)
        {
            path = null;

            if (!reader.TryReadTo(out ReadOnlySpan<byte> _, (byte)'<')) return false;
            if (!reader.TryReadTo(out ReadOnlySpan<byte> content, (byte)'>')) return false;

            path = Encoding.UTF8.GetString(content).Trim();

            // Handling für RFC 5321 Source-Routing (z.B. "@host1,@host2:user@domain")
            // Ein Source Route MUSS mit '@' beginnen.
            if (path.StartsWith('@'))
            {
                int colonIndex = path.IndexOf(':');
                if (colonIndex != -1)
                {
                    // Wir schneiden den Routing-Teil ab und behalten nur die eigentliche Adresse dahinter
                    path = path.Substring(colonIndex + 1);
                }
            }

            return true;
        }

        private static IMailbox ParseMailbox(string mailboxStr)
        {
            if (string.IsNullOrEmpty(mailboxStr))
            {
                return Mailbox.Empty;
            }

            int lastAt = mailboxStr.LastIndexOf('@');
            if (lastAt > 0)
            {
                string user = mailboxStr.Substring(0, lastAt);
                string host = mailboxStr.Substring(lastAt + 1);

                if (user.StartsWith('"') && user.EndsWith('"') && user.Length >= 2)
                {
                    user = user.Substring(1, user.Length - 2);
                }

                return new Mailbox(user, host);
            }

            return new Mailbox(mailboxStr, string.Empty);
        }

        private static Dictionary<string, string> ParseParameters(ref SequenceReader<byte> reader)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            SkipWhitespace(ref reader);

            if (reader.Remaining == 0) return parameters;

            string paramStr = ReadLineAsString(reader.Sequence.Slice(reader.Position)).Trim('\r', '\n', ' ');
            if (string.IsNullOrWhiteSpace(paramStr)) return parameters;

            var paramTokens = paramStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var token in paramTokens)
            {
                var kvp = token.Split('=', 2);
                parameters[kvp[0]] = kvp.Length > 1 ? kvp[1] : string.Empty;
            }

            return parameters;
        }

        private static string ReadLineAsString(ReadOnlySequence<byte> sequence)
        {
            if (sequence.IsSingleSegment)
            {
                return Encoding.UTF8.GetString(sequence.FirstSpan);
            }

            return Encoding.UTF8.GetString(sequence.ToArray());
        }

        private static bool IsValidDomainOrHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            if (host.StartsWith('-') || host.EndsWith('.') || host.Contains("..") || host.Contains("//"))
            {
                return false;
            }
            return true;
        }
    }
}
