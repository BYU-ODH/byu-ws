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
;; curl -v -k -u "client_id:client_secret" -d "grant_type=authorization_code&code=authorization code&redirect_uri=redirect_uri" https://api.byu.edu/token
(defn stage2-request [& [{:keys [client-id client-secret authorization-code redirect-uri]}]]
  ;; how to post user info?
  (let [url "https://api.byu.edu/token"]
    (client/post url {:basic-auth [client-id client-secret]
                      :form-params {"grant_type" "authorization_code"
                                    "code" authorization-code
                                    "redirect_uri" redirect-uri}})))


(def returned-jwt "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJieXVcL3RvcnlzYUBjYXJib24uc3VwZXIiLCJhenAiOiJxOXZGVzFTbVNmNUlETVVOSjdUeGR3VFpDVHNhIiwicGVyc29uX2lkIjoiMDgxMjcwMjMyIiwiYXRfaGFzaCI6Ill6bGhNR1JqTlRSallXTTJPR0V5TldabE16QmlOVGcyTXpGaU56RmlOQT09IiwiaXNzIjoiaHR0cHM6XC9cL3dzbzItaXMuYnl1LmVkdVwvb2F1dGgyZW5kcG9pbnRzXC90b2tlbiIsInN1cm5hbWUiOiJBbmRlcnNvbiIsInByZWZlcnJlZF9maXJzdF9uYW1lIjoiVG9yeSIsInJlc3Rfb2ZfbmFtZSI6IlRvcnkgU2hlcm1hbiIsIm5ldF9pZCI6InRvcnlzYSIsImlhdCI6MTQ3MDE3OTY1OTMxNSwic3VmZml4IjoiICIsInNvcnRfbmFtZSI6IkFuZGVyc29uLCBUb3J5IFNoZXJtYW4iLCJhdXRoX3RpbWUiOjE0NzAxNzk2NTkzMTAsImV4cCI6MTQ3MDE4MzI1OTMxNSwicHJlZml4IjoiICIsInN1cm5hbWVfcG9zaXRpb24iOiJMIiwiYXVkIjpbInE5dkZXMVNtU2Y1SURNVU5KN1R4ZHdUWkNUc2EiXSwiYnl1X2lkIjoiMTk5NzMzMDM0In0.IGWAoexDZ_4NBgirqGSPXa_9W3CcdIfUlky4skokO9VKyijVbYOpbvyHvq9i4mTvv9EopQlBBB2zEAF2bWIgqObJbTpcw7IxgHKih4zxHwBnKuYOpr3Xnsk_-s_3SnFP1uFcY8lS18SCYeY7RjZAP_0CBL4osMAEkJMJMB2yY6xYNqZrKFIpNvLnTbksjFV8YlcTH00DMHMRilA6xRlY6M79gCMfoVWHeBZDNdVoRvsZTWvMKwRkqdctwTEH5VbuDIzyzBGwrQVxzhCgriiIraaMVEAgjlvwGvoxDH4gIifADYGCy_xuUbEksMWU2BhY92orNyAZLOi_RL7AXu0s1A")

;; returned https://humplus-funding.byu.edu/?state=myteststate&code=851f891d89299beb0657aeefc64540

;; curl -v -k -u "q9vFW1SmSf5IDMUNJ7TxdwTZCTsa:3W1RyHVntmFxD7q6Pecdb63h4_oa" -d "grant_type=authorization_code&code=851f891d89299beb0657aeefc64540&redirect_uri=https://humplus-funding.byu.edu" https://api.byu.edu/token

;; curl -v -k -H "Authorization: Bearer c9a0dc54cac68a25fe30b58631b71b4" https://api.byu.edu/byuapi/personsummary/v1/torysa

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
