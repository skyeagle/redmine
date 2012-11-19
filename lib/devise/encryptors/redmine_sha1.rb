require 'digest/sha1'

module Devise
  module Encryptable
    module Encryptors
      class RedmineSha1 < Base
        def self.digest(password, stretches, salt, pepper)
          hash_password("#{salt}#{hash_password(password)}")
        end

        def self.salt stretches = nil
          Redmine::Utils.random_hex(16)
        end

        def self.hash_password clear_password
          Digest::SHA1.hexdigest(clear_password || "")
        end
      end
    end
  end
end
