require "openssl"
require "digest"

# Suppress warning messages
original_verbose, $VERBOSE = $VERBOSE, nil

# override the default Digest with OpenSSL::Digest
Digest::SHA256 = OpenSSL::Digest::SHA256
Digest::SHA1 = OpenSSL::Digest::SHA1

# Activate warning messages again
$VERBOSE = original_verbose

# enable FIPS mode
OpenSSL.fips_mode = true

# each of the following 3rd party overridden is required since a non FIPS complaint encryption method is used
# if a non-complaint FIPS method like MD5 is used or a direct use of Digest::encryption-method
#  (rather than OpenSSL::Digest::encryption-method) is performed
#  the server will crush on run time

# override ActiveSupport hash_digest_class with FIPS complaint method
ActiveSupport::Digest.hash_digest_class = OpenSSL::Digest::SHA1.new

# override OpenIDConnect cache_key with FIPS complaint method
OpenIDConnect::Discovery::Provider::Config::Resource.module_eval do
  def cache_key
    sha256 = Digest::SHA256.hexdigest host
    "swd:resource:opneid-conf:#{sha256}"
  end
end
