module Authentication
  module AuthnAzure

    Log = LogMessages::Authentication::AuthnAzure
    Err = Errors::Authentication::AuthnAzure

    class ApplicationIdentity

      attr_reader :resources, :resource_types

      def initialize(role_annotations:, service_id:, azure_resource_types:, logger:)
        @role_annotations = role_annotations
        @service_id       = service_id
        @azure_resource_types = azure_resource_types
        @logger           = logger

        init_resources
      end

      private

      def init_resources
        @resource_types = []
        @resources = @azure_resource_types.each_with_object([]) do |resource_type, resources|
          resource_name = resource_name(resource_type)
          if resource_name
            resources.push(
              AzureResource.new(
                resource_type: resource_type,
                resource_name: resource_name
              )
            )
            @resource_types.push(resource_type)
          end
        end
      end

      # check the `service-id` specific resource first to be more granular
      def resource_name resource_type
        annotation_value("authn-azure/#{@service_id}/#{resource_type}") ||
          annotation_value("authn-azure/#{resource_type}")
      end

      def annotation_value name
        annotation = @role_annotations.find { |a| a.values[:name] == name }

        # return the value of the annotation if it exists, nil otherwise
        if annotation
          @logger.debug(LogMessages::Authentication::RetrievedAnnotationValue.new(name))
          annotation[:value]
        end
      end
    end
  end
end
