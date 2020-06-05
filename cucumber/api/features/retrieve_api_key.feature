Feature: Retrieving an API key with conjurctl

  # We need to be in production environment to test this
  Scenario: Retrieve an API key
    Given I set environment variable "RAILS_ENV" to "production"
    And I set environment variable "CONJUR_LOG_LEVEL" to "info"
    When I retrieve an API key using conjurctl
    Then the API key is correct
