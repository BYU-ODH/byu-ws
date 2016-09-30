(ns byu-ws.oauth2
  (:require [clj-http.client :as client :refer [post]]
            [cheshire.core :as json]
            [buddy.sign.jwt :as jwt]
            [buddy.core.hash :as hash])
  (:import [java.net URL]
           [io.jsonwebtoken Jwts]
           [io.jsonwebtoken SignatureAlgorithm]
           [io.jsonwebtoken.impl.crypto MacProvider]
           [java.security Key]
           [org.apache.commons.codec.binary Base64]))

(def authorize-url "https://api.byu.edu/authorize")
(def token-url "https://api.byu.edu/token")

(defn authkey-GET-url 
  "1. (in browser) the following ultimately results in a redirect which will have the auth code"
  [client-id associated-url]
  (str
   "https://api.byu.edu/authorize?response_type=code&client_id="
   client-id
   "&redirect_uri="
   associated-url
   "&scope=openid&state=myteststate"))

;; 2. Having returned something with state and code url parameters, now use that code along with your key and secret to post for the juicy stuff
;; curl -v -k -u "client_id:client_secret" -d "grant_type=authorization_code&code=<authorization-code>&redirect_uri=<redirect-uri>" https://api.byu.edu/token
(defn stage2-request [& [{:keys [client-id client-secret authorization-code redirect-uri]}]]
  ;; how to post user info?
  (let [url "https://api.byu.edu/token"]
    (client/post url {:basic-auth [client-id client-secret]
                      :form-params {"grant_type" "authorization_code"
                                    "code" authorization-code
                                    "redirect_uri" redirect-uri}})))


(defn get-jwt-body
  "A cheap extraction of a base-64 jwt body, without checking signatures."
  [returned-jwt]
  (-> returned-jwt ;; returned-jwt is your full jwt string
      (clojure.string/split #"\.") ;; split into the 3 parts of a jwt, header, body, signature
      second ;; get the body
      Base64/decodeBase64 ;; read it into a byte array
      String. ;; byte array to string
      json/decode ;; make it into a sensible clojure map
      ))

(defn api-user-data
  "Already having an auth code, obtain and decrypt the user data from a token request. Takes a map as: 
  {:client-id <STR>,
   :client-secret <STR>,
   :redirect-uri <STR>,
   :authorization-code <STR>}"
  [post-map]
  (let [post-response (stage2-request post-map)]
    (-> post-response
        :body
        json/decode
        (get "id_token") ;; the actual JWT
        get-jwt-body)))
