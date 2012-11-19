class Users::SessionsController < Devise::SessionsController

  def create
    if !user_signed_in? && params[:user] and (url = params[:user][:identity_url]).present?
      redirect_to user_omniauth_authorize_path(:open_id, :openid_url => url)
      return
    end
    super
  end
end

