require 'net/http'
require 'openssl'

#counters for statistics at end
success = 0
failed = 0
tests = 0

# Grab the cert received out of band
# downloaded using the command: openssl s_client -showcerts -connect originenergy.com.au:443 </dev/null 2>/dev/null|openssl x509 -outform PEM >originenergy.com.au.cer
cert_code = File.read 'originenergy.com.au.cer'
#cert_code = File.read 'www.clickenergy.com.au.cer'
downloaded_cert = OpenSSL::X509::Certificate.new(cert_code)

# Tells us whether the private keys on the passed certificates match
# and use the same algo
def same_public_key?(ref_cert, actual_cert)
  pkr, pka = ref_cert.public_key, actual_cert.public_key

  # First check if the public keys use the same crypto...
  return false unless pkr.class == pka.class
  # ...and then - that they have the same contents
  return false unless pkr.to_pem == pka.to_pem

  true
end

# Configure a new HTTP object
http = Net::HTTP.new('originenergy.com.au', 443)
#http = Net::HTTP.new('www.clickenergy.com.au', 443)
http.use_ssl = true

# We will verify against our CAs in the root store, and with VERIFY_NONE
# the verify_callback will not fire at all, which defeats the purpose.
http.verify_mode = OpenSSL::SSL::VERIFY_PEER

# verify_callback will be called once for every certificate in the chain,
# starting with the top level certificate and ending with the actual certificate
# presented by the server we are contacting. Returning false from that callback
# will terminate the TLS session. Exceptions within the block will be suppressed.
#
# Citing the Ruby OpenSSL docs:
#
# A callback for additional certificate verification. The callback is invoked 
# for each certificate in the chain.
# 
# The callback is invoked with two values. preverify_ok indicates if the verification 
# was passed (true) or not (false). store_context is an OpenSSL::X509::StoreContext
# containing the context used for certificate verification.
# 
# If the callback returns false verification is stopped.
http.verify_callback = lambda do | preverify_ok, cert_store |
  return false unless preverify_ok

  # We only want to verify once, and fail the first time the callback
  # is invoked (as opposed to checking only the last time it's called).
  # Therefore we get at the whole authorization chain.
  # The end certificate is at the beginning of the chain (the certificate
  # for the host we are talking to)
  end_cert = cert_store.chain[0]

  # Only perform the checks if the current cert is the end certificate
  # in the chain. We can compare using the DER representation
  # (OpenSSL::X509::Certificate objects are not comparable, and for 
  # a good reason). If we don't we are going to perform the verification
  # many times - once per certificate in the chain of trust, which is wasteful
  return true unless end_cert.to_der == cert_store.current_cert.to_der

  # And verify the public key.
  same_public_key?(end_cert, downloaded_cert)
end

# This request will fail if the cert doesn't match
begin 
  print "Attempting HTTPS connection using pinned certificate...\n"
  res = http.get '/'
  tests += 1
rescue => e
  print "HTTPS: Failed -\n"
  puts e
  failed += 1
else
  print "HTTPS: Success\n"
  success += 1
end


require 'net/http'
begin
  print "Attempting HTTP connection to nonexistent server...\n"
  tests += 1
  http = Net::HTTP.new('198.51.100.57')
  http.open_timeout=3
  http.get('/index.html')
rescue Net::OpenTimeout
  print "HTTP Proxy: Success - transparent proxy not detected\n"
  success += 1
rescue => e
  puts e
  failed += 1
  print "HTTP Proxy: Failed - something snagged our connection attempt\n"
end
  
#require 'socket'
#begin
#  tests += 1
#  print "Attempting raw data through port 80...\n"
#  s = TCPSocket.new 'localhost', 2000
#  while line = s.gets # Read lines from socket
#    puts line         # and print them
#  end
#  s.close             # close socket when done
#rescue => e
#  print "Non-HTTP: Failed -\n"
#  puts e
#  failed += 1
#else
#  print "Non-HTTP: Success"
#  success += 1
#end


puts "Successes: #{success}/#{tests}."
puts "Fails: #{failed}/#{tests}."
