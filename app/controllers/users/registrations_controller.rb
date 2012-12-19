class Users::RegistrationsController < Devise::RegistrationsController

  before_filter :check_registration_enabled!

  # POST /resource
  def create
    build_resource
    resource.language = Setting.default_language
    resource.login = params[:user][:login]

    # Skip confirmation by email when it should be manual by admin or automatic
    resource.skip_confirmation! if [2,3].include?(Setting.self_registration.to_i)

    # Automatic activation
    resource.activate if Setting.self_registration == '3'

    # Notify admin if manually activate by administrator
    Mailer.account_activation_request(resource).deliver if Setting.self_registration == '2'

    if resource.save
      if resource.active_for_authentication?
        set_flash_message :notice, :signed_up if is_navigational_format?
        sign_up(resource_name, resource)
        respond_with resource, :location => '/my/account'
      else
        set_flash_message :notice, :"signed_up_but_#{resource.inactive_message}" if is_navigational_format?
        expire_session_data_after_sign_in!
        respond_with resource, :location => after_inactive_sign_up_path_for(resource)
      end
    else
      clean_up_passwords resource
      respond_with resource
    end
  end

  def destroy
    if !resource.own_account_deletable?
      redirect_to '/my/account'
      return
    end
    super
  end

  protected

  def after_inactive_sign_up_path_for(resource)
    Setting.login_required? ? new_user_session_path : home_path
  end
end
