require 'jwt'

module OAuth2
  module Strategy
    # The JWT-Bearer Assertion Strategy
    #
    # @see https://tools.ietf.org/html/rfc7523
    #
    # Sample usage:
    #   client = OAuth2::Client.new(client_id, client_secret,
    #                               :site => 'http://localhost:8080')
    #
    #   params = {:hmac_secret => "some secret",
    #             # or :private_key => "private key string",
    #             :iss => "http://localhost:3001",
    #             :sub => "me@here.com",
    #             :aud => "http://localhost:8080/token"
    #             :exp => Time.now.utc.to_i + 3600}
    #
    #   access = client.jwt_bearer.get_token(params)
    #   access.token                 # actual access_token string
    #   access.get("/api/stuff")     # making api calls with access token in header
    #
    class JWTBearer < Base
      # Not used for this strategy
      #
      # @raise [NotImplementedError]
      def authorize_url
        raise(NotImplementedError, 'The authorization endpoint is not used in this strategy')
      end

      # Retrieve an access token given the specified client.
      #
      # @param [Hash] params jwt_bearer params
      # pass either :hmac_secret or :private_key, but not both.
      #
      #   params :hmac_secret, secret string.
      #   params :private_key, private key string.
      #
      #   params :iss, issuer
      #   params :aud, audience, optional
      #   params :sub, principal, current user
      #   params :exp, expired at, in seconds, like Time.now.utc.to_i + 3600
      #
      # @param [Hash] opts options
      def get_token(params = {}, opts = {})
        hash = build_request(params)
        @client.get_token(hash, opts.merge('refresh_token' => nil))
      end

      # Build the request for an access token
      #
      # @param [Hash] params jwt_bearer params
      # pass either :hmac_secret or :private_key, but not both.
      #
      #   params :hmac_secret, secret string.
      #   params :private_key, private key string.
      #
      #   params :iss, issuer
      #   params :aud, audience, optional
      #   params :sub, principal, current user
      #   params :exp, expired at, in seconds, like Time.now.utc.to_i + 3600
      def build_request(params)
        assertion = build_assertion(params)
        {
          :grant_type     => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          :assertion      => assertion,
          :scope          => params[:scope],
        }
      end

      # Build the JWT used as the authorization assertion
      #
      # @param [Hash] params jwt_bearer params
      # pass either :hmac_secret or :private_key, but not both.
      #
      #   params :hmac_secret, secret string.
      #   params :private_key, private key string.
      #
      #   params :iss, issuer
      #   params :aud, audience, optional
      #   params :sub, principal, current user
      #   params :exp, expired at, in seconds, like Time.now.utc.to_i + 3600
      def build_assertion(params)
        claims = {
          :iss => params[:iss],
          :aud => params[:aud],
          :sub => params[:sub],
          :exp => params[:exp],
        }
        if params[:hmac_secret]
          JWT.encode(claims, params[:hmac_secret], 'HS256')
        elsif params[:private_key]
          JWT.encode(claims, params[:private_key], 'RS256')
        end
      end
    end
  end
end
