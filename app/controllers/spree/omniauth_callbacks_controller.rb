class Spree::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  include Spree::Core::CurrentOrder
  include Spree::Core::ControllerHelpers

  def self.provides_callback_for(*providers)
    providers.each do |provider|
      class_eval %Q{
        def #{provider}
          if request.env["omniauth.error"].present?
            flash[:error] = t("devise.omniauth_callbacks.failure", :kind => auth_hash['provider'], :reason => t(:user_was_not_valid))
            redirect_back_or_default(root_url)
            return
          end

          authentication = Spree::UserAuthentication.find_by_provider_and_uid(auth_hash['provider'], auth_hash['uid'])

          if authentication.present?
            flash[:notice] = "Signed in successfully"
            sign_in_and_redirect :user, authentication.user
          elsif current_user
            current_user.user_authentications.create!(:provider => auth_hash['provider'], :uid => auth_hash['uid'])
            flash[:notice] = "Authentication successful."
            redirect_back_or_default(account_url)
          else
            user = Spree::User.find_by_email(auth_hash['info']['email']) || Spree::User.new
            user.apply_omniauth(auth_hash)
            if user.save
              flash[:notice] = "Signed in successfully."
              sign_in_and_redirect :user, user
            else
              session[:omniauth] = auth_hash.except('extra')
              flash[:notice] = t(:one_more_step, :kind => auth_hash['provider'].capitalize)
              redirect_to new_user_registration_url
            end
          end

          if current_order
            user = current_user if current_user
            current_order.associate_user!(user)
            session[:guest_token] = nil
          end

          if current_user
            spree_user = Spree::User.find(current_user.id)
            fields = ["first_name", "last_name", "email"]
            conf = YAML.load_file("#{Rails.root}/config/facebook.yml")[Rails.env]
            app_id = conf["app_id"]
            app_secret = conf["client_secret"]
            fb_auth = FbGraph::Auth.new(app_id, app_secret)
            unless cookies[:"fbsr_\#{app_id}"].blank?
              fb_auth.from_cookie(cookies)
              user = fb_auth.user.fetch
              user.location = user.location.name.split(',')
              current_user.city = user.location[0]
              current_user.country = user.location[1]
              fields.each do |info|
                if spree_user.send(info).nil?
                  spree_user[:"\#{info}"] = user.send(info)
                end
              end
              spree_user.save
            end
          end
        end
      }
    end
  end

  SpreeSocial::OAUTH_PROVIDERS.each do |provider|
    provides_callback_for provider[1].to_sym
  end

  def failure
    set_flash_message :alert, :failure, :kind => failed_strategy.name.to_s.humanize, :reason => failure_message
    redirect_to spree.login_path
  end

  def passthru
    render :file => "#{Rails.root}/public/404", :formats => [:html], :status => 404, :layout => false
  end

  def auth_hash
    request.env["omniauth.auth"]
  end
end
