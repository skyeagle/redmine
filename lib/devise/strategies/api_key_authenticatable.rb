require 'devise/strategies/base'

module Devise
  module Strategies
    class ApiKeyAuthenticatable < Authenticatable

      def store?
        super && !mapping.to.skip_session_storage.include?(:api_auth)
      end

      def authenticate!
        resource = mapping.to.find_by_api_key(authentication_hash[:key])
        return fail(:invalid_token) unless resource

        success!(resource)
      end

      def valid?
        api_enabled? && valid_controller_and_action? && super
      end

      private

      def valid_params_request?
        true
      end

      def valid_params?
        params[:key].present? || request.headers["X-Redmine-API-Key"].present?
      end

      def api_enabled?
        mapping.to.settings_available? && Setting.rest_api_enabled?
      end

      def valid_controller_and_action?
        return false unless params[:controller]
        controller = "#{params[:controller]}_controller".camelize.constantize
        controller.accept_api_auth.include?(params[:action].to_sym)
      end

      def remember_me?
        false
      end

      # Try both scoped and non scoped keys.
      def params_auth_hash
        if !params[:key] && (key = request.headers["X-Redmine-API-Key"]).present?
          params.merge!({ :key => key })
        end
        params
      end

      def authentication_keys
        @authentication_keys ||= [:key]
      end
    end
  end
  module Models::ApiKeyAuthenticatable
  end
end

Warden::Strategies.add(:api_key_authenticatable, Devise::Strategies::ApiKeyAuthenticatable)
