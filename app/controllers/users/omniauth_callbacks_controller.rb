class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  skip_before_filter :verify_authenticity_token, :only => [:open_id]

  def open_id

    @user = User.find_for_open_id(request.env["omniauth.auth"], current_user)

    if @user && @user.persisted?
      if @user.active_for_authentication?
        flash[:notice] = I18n.t "devise.omniauth_callbacks.success", :kind => "Open ID"
        sign_in_and_redirect @user, :event => :authentication
      else
        expire_data_after_sign_in!
        set_flash_message :notice, :"signed_up_but_#{@user.inactive_message}"
        redirect_to new_user_session_url
      end
    else
      if registration_disabled?
        redirect_to new_user_session_path
        return
      end
      if @user
        data = @user.attributes.with_indifferent_access.slice(:login, :email, :firstname, :lastname)
        session["devise.open_id_data"] = data
      end
      redirect_to new_user_registration_url
    end
  end
end
