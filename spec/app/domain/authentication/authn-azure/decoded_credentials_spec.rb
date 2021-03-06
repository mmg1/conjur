# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Authentication::AuthnAzure::DecodedCredentials' do

  ####################################
  # request mock
  ####################################

  def mock_authenticate_azure_token_request(request_body_data:)
    double('AuthnAzureRequest').tap do |request|
      request_body = StringIO.new
      request_body.puts request_body_data
      request_body.rewind

      allow(request).to receive(:body).and_return(request_body)
    end
  end

  def request_body(request)
    request.body.read.chomp
  end

  let(:valid_jwt_field_value) do
    "{\"xms_mirid\": \"some_xms_mirid_value\", \"oid\": \"some_oid_value\"}"
  end

  let(:authenticate_azure_token_request) do
    mock_authenticate_azure_token_request(request_body_data: "jwt=#{valid_jwt_field_value}")
  end

  let(:authenticate_azure_token_request_missing_jwt_field) do
    mock_authenticate_azure_token_request(request_body_data: "some_key=some_value")
  end

  let(:authenticate_azure_token_request_empty_jwt_field) do
    mock_authenticate_azure_token_request(request_body_data: "jwt=")
  end

  #  ____  _   _  ____    ____  ____  ___  ____  ___
  # (_  _)( )_( )( ___)  (_  _)( ___)/ __)(_  _)/ __)
  #   )(   ) _ (  )__)     )(   )__) \__ \  )(  \__ \
  #  (__) (_) (_)(____)   (__) (____)(___/ (__) (___/


  context "Credentials" do
    context "with a jwt field" do
      subject(:decoded_credentials) do
        ::Authentication::AuthnAzure::DecodedCredentials.new(
          request_body(authenticate_azure_token_request)
        )
      end

      it "does not raise an error" do
        expect { decoded_credentials }.to_not raise_error
      end

      it "parses the jwt field expectedly" do
        expect(decoded_credentials.jwt).to eq(valid_jwt_field_value)
      end
    end

    context "with no jwt field in the request" do
      subject do
        ::Authentication::AuthnAzure::DecodedCredentials.new(
          request_body(authenticate_azure_token_request_missing_jwt_field)
        )
      end

      it "raises a MissingRequestParam error" do
        expect { subject }.to raise_error(::Errors::Authentication::RequestBody::MissingRequestParam)
      end
    end

    context "with an empty jwt field in the request" do
      subject do
        ::Authentication::AuthnAzure::DecodedCredentials.new(
          request_body(authenticate_azure_token_request_empty_jwt_field)
        )
      end

      it "raises a MissingRequestParam error" do
        expect { subject }.to raise_error(::Errors::Authentication::RequestBody::MissingRequestParam)
      end
    end
  end
end
