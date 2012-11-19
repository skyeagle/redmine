module OpenIdAuthentication

  def mock_existen_user_openid_authentication
    @user = users(:users_002)
    request.env["omniauth.auth"] = OmniAuth.config.mock_auth[:open_id] = OmniAuth::AuthHash.new({
      :provider => 'open_id',
      :uid => @user.identity_url,
      :info => {
        :email    => @user.email,
        :nickname => @user.login,
        :name     => @user.name
      }
    })
  end

  def mock_new_user_openid_authentication
    request.env["omniauth.auth"] = OmniAuth.config.mock_auth[:open_id] = OmniAuth::AuthHash.new({
      :provider => 'open_id',
      :uid => 'http://uid.unexistent.net',
      :info => {
        :email => 'abc@abc.com',
        :nickname => 'newuser',
        :name => 'New User'
      }
    })
  end

  def mock_new_user_openid_authentication_with_invalid_data
    request.env["omniauth.auth"] = OmniAuth.config.mock_auth[:open_id] = OmniAuth::AuthHash.new({
      :provider => 'open_id',
      :uid => 'http://uid.unexistent.net',
      :info => {
        #there is empty for stubing invalid credentials or their absence
      }
    })
  end

end
