# frozen_string_literal: true

module Audit
  class << self
    # TODO: Think about this more
    def logger
      @logger ||= Rails.logger
    end

    attr_writer :logger
  end
end
