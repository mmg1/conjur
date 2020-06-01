module Authentication
  module AuthnK8s

    class K8sResource
      attr_reader :resource_type, :resource_name

      def initialize(resource_type:, resource_name:)
        @resource_type = resource_type
        @resource_name = resource_name
      end
    end
  end
end
