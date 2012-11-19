require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    # Default strategy for signing in a user, based on his email and password in the database.
    class DatabaseAuthenticatable < Authenticatable
      def authenticate!
        resource = valid_password? && mapping.to.find_for_database_authentication(authentication_hash)
        return fail(:invalid_email) unless resource

        if validate(resource){ resource.valid_password?(password) }
          resource.after_database_authentication
          success!(resource)
        end
      end

      def valid?
        validate_api_request && super
      end

      private

      def validate_api_request
        api_request? ? api_enabled? :  true
      end

      def api_enabled?
        Setting.rest_api_enabled == '1'
      end

      def api_request?
        %w(xml json).include?(params[:format])
      end
    end
  end
end

Warden::Strategies.add(:database_authenticatable, Devise::Strategies::DatabaseAuthenticatable)
