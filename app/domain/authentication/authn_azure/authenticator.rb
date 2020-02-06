require 'command_class'

module Authentication
  module AuthnAzure

    Err = Errors::Authentication::AuthnAzure
    Log = LogMessages::Authentication::AuthnAzure
    # Possible Errors Raised:
    # TODO: Add errors

    Authenticator = CommandClass.new(
      dependencies: {

      },
      inputs: [:authenticator_input]
    ) do
      extend Forwardable
      def_delegators :@authenticator_input, :service_id, :authenticator_name, :account, :username, :request, :credentials

      def call
        validate_azure_token
        validate_application_identity
      end

      private

      def validate_azure_token

      end

      def validate_application_identity

      end
    end

    class Authenticator
      # This delegates to all the work to the call method created automatically
      # by CommandClass
      #
      # This is needed because we need `valid?` to exist on the Authenticator
      # class, but that class contains only a metaprogramming generated
      # `call(authenticator_input:)` method.  The methods we define in the
      # block passed to `CommandClass` exist only on the private internal
      # `Call` objects created each time `call` is run.
      #
      def valid?(input)
        call(authenticator_input: input)
      end
    end
  end
end