# facility:
#   The type of program that is logging the message. An RFC5424-specified
#   numeric code.
#   See: https://tools.ietf.org/html/rfc5424#section-6.2.1
#
# message_id:
#   The MSGID SHOULD identify the type of message.  For example, a firewall
#   might use the MSGID "TCPIN" for incoming TCP traffic and the MSGID
#   "TCPOUT" for outgoing TCP traffic.  Messages with the same MSGID should
#   reflect events of the same semantics.
#   See: https://tools.ietf.org/html/rfc5424#section-6.2.7
#
# message:
#   The MSG part contains a free-form message that provides information about
#   the event.
#
# severity:
#   An RFC5424-specified numeric code.
#   See: https://tools.ietf.org/html/rfc5424#section-6.2.1
#
module Audit
  class Event2

    # "progname" is required by ruby's Syslog::Logger interface. See:
    # https://ruby-doc.org/stdlib-2.6.3/libdoc/syslog/rdoc/Syslog/Logger.html#method-i-add
    PROG_NAME = "conjur"

    attr_reader :facility, :message, :message_id, :severity, :structured_data

    def initialize(
        facility:,
        message:,
        message_id:,
        severity:,
        structured_data:
    )
      @facility = facility
      @message = message
      @message_id = message_id
      @severity = severity
      @structured_data = structured_data
    end
  end
end
