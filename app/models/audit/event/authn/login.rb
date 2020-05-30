require 'forwardable'

module Audit
  module Event2
    class Authn
      class Login

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
            operation: "login"
          )
        end

        def to_s
          message
        end

        def message
          @authn.message(
            success_msg:
              "##{@role&.id} successfully logged in with authenticator " \
                "#{@authn.authenticator_description}",
            failure_msg:
              "#{@role&.id} failed to login with authenticator " \
                "#{@authn.authenticator_description}",
            error_msg: @error_message
          )
        end
      end
    end
  end
end
