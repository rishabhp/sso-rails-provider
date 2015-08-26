class Client < ActiveRecord::Base

  # Check whether a Client exists by app_id and app_secret
  def self.authenticate(app_id, app_secret)
    where(["app_id = ? AND app_secret = ?", app_id, app_secret]).first
  end
end
