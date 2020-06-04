require 'forwardable'

module Audit
  module Event2
    class Authn
      class Authenticate
        attr_reader :authenticator_name, :service, :success, :error_message

        extend Forwardable
        def_delegators :@authn, :facility, :message_id, :severity,
                       :structured_data, :progname

        def initialize(
          role:,
          authenticator_name:,
          service:,
          success:,
          error_message: nil
        )
          @role = role
          @error_message = error_message
          @authn = Authn.new(
            role: role,
            authenticator_name: authenticator_name,
            service: service,
            success: success,
            operation: "authenticate"
          )
        end

        # TODO: This won't be needed if we fix the RFC5424 formatter
        def to_s
          message
        end

        def message
          @authn.message(
              success_msg:
                "#{@role&.id} successfully authenticated with authenticator " \
                "#{@authn.authenticator_description}",
              failure_msg:
                "#{@role&.id} failed to authenticate with authenticator "\
                "#{@authn.authenticator_description}",
              error_msg: @error_message
          )
        end
      end
    end
  end
end
