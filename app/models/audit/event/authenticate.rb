require 'forwardable'

module Audit
  module Event2
    class Authn
      class Authenticate

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
          @error_message = error_message
          @authn = Authn.new(
            role: role,
            authenticator_name: authenticator_name,
            service: service,
            success: success,
            operation: "authenticate"
          )
        end

        # TODO: move to shared object; then delete entirely (update all calling
        #   sites)
        def log_to(logger)
          logger.log(severity, self, Event2::progname)
        end

        def to_s
          message
        end

        def message
          @authn.message(
              success_msg: success_msg,
              failure_msg: failure_msg,
              error_msg: @error_message
          )
        end

        private

        def success_msg
          "#{@role&.id} successfully authenticated with authenticator " \
          "#{@authn.authenticator_description}"
        end

        def failure_msg
          "#{@role&.id} failed to authenticate with authenticator "\
          "#{@authn.authenticator_description}"
        end
      end
    end
  end
end
