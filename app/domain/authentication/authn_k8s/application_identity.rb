# frozen_string_literal: true

module Authentication
  module AuthnK8s

    Log = LogMessages::Authentication::AuthnK8s
    Err = Errors::Authentication::AuthnK8s

    # This class defines an application identity of a given Conjur host
    class ApplicationIdentity

      attr_reader :resources, :resource_types
      
      def initialize(host_id:, host_annotations:, service_id:, application_identity_in_annotations:, k8s_resource_types:, logger:)
        @host_id          = host_id
        @host_annotations = host_annotations
        @service_id       = service_id
        @application_identity_in_annotations = application_identity_in_annotations
        @k8s_resource_types = k8s_resource_types
        @logger           = logger

        init_resources
      end

      private

      def init_resources
        @resource_types = []
        @resources = @k8s_resource_types.each_with_object([]) do |resource_type, resources|
          resource_name = resource_name(resource_type)
          if resource_name
            resources.push(
              K8sResource.new(
                resource_type: resource_type,
                resource_name: resource_name
              )
            )
            @resource_types.push(resource_type)
          end
        end
      end

      def resource_name resource_type
        @application_identity_in_annotations ? resource_from_annotation(resource_type) : resource_from_id(underscored_resource_type(resource_type))
      end

      def resource_from_annotation resource_type
        annotation_value("authn-k8s/#{@service_id}/#{resource_type}") ||
          annotation_value("authn-k8s/#{resource_type}")
      end

      def annotation_value name
        annotation = @host_annotations.find { |a| a.values[:name] == name }

        # return the value of the annotation if it exists, nil otherwise
        if annotation
          @logger.debug(LogMessages::Authentication::RetrievedAnnotationValue.new(name))
          annotation[:value]
        end
      end

      def resource_from_id resource_type
        return @host_id[-3] if resource_type == "namespace"
        @host_id[-2] == resource_type ? @host_id[-1] : nil
      end

      def underscored_resource_type resource_type
        resource_type.tr('-', '_')
      end
    end
  end
end
