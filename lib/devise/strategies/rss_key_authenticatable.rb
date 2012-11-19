require 'devise/strategies/base'

module Devise
  module Strategies
    class RssKeyAuthenticatable < Authenticatable

      def store?
        super && !mapping.to.skip_session_storage.include?(:rss_auth)
      end

      def authenticate!
        resource = mapping.to.find_by_rss_key(authentication_hash[:key])
        return fail(:invalid_token) unless resource

        success!(resource)
      end

      def valid?
        valid_controller_and_action? && params[:format] == 'atom' && request.get? && super
      end

      private

      def valid_params?
        params[:key].present?
      end

      def valid_params_request?
        true
      end

      def params_auth_hash
        params
      end

      def valid_controller_and_action?
        return false unless params[:controller]
        controller = "#{params[:controller]}_controller".camelize.constantize
        controller.accept_rss_auth.include?(params[:action].to_sym)
      end

      def remember_me?
        false
      end

      def authentication_keys
        @authentication_keys ||= [:key]
      end
    end
  end
  module Models::RssKeyAuthenticatable
  end
end

Warden::Strategies.add(:rss_key_authenticatable, Devise::Strategies::RssKeyAuthenticatable)
