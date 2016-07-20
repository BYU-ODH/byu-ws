(ns byu-ws.core
  (:require [clj-http.client :as client]
            [cheshire.core :as json])
  (:import [java.net URL]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(def VALID-KEY-TYPES #{"API" "WsSession"})

(def DATE-FORMAT (java.text.SimpleDateFormat. "YYYY-MM-dd HH:mm:ss"))

(def SERVICE-URLS {:records "https://api.byu.edu/rest/v1/apikey/academic/records/studentrecord/" 
                       :schedule "https://ws.byu.edu/rest/v1.0/academic/registration/studentschedule/"
                       })

(defn make-sha512-hmac
  "Produce a base-64 encoded sha512 hmac, as per https://byuapi.atlassian.net/wiki/display/OITCoreDeveloperResources/Web+Service+using+Nonce-Encoded+HMAC+Signed+by+an+API+Key+Tutorial"
  [shared-secret item-to-encode]
  (let [algorithm "HmacSHA512"
        key-spec (SecretKeySpec. (.getBytes shared-secret "UTF8") algorithm)
        mac (Mac/getInstance (.getAlgorithm key-spec))
        _ (.init mac key-spec)
        encoder (new org.apache.commons.codec.binary.Base64 0)]
    (-> item-to-encode
        (.getBytes "UTF8")
        (->> (.doFinal mac)
             (.encodeToString encoder)))))

(defn url-encode ;; XX TODO not fully compatible with make-sha512-hmac
  "Encode for URL validation"
  [[{:keys [shared-secret
            current-timestamp
            url
            request-body
            content-type
            http-method
            actor
            actor-in-hash]}]]
  (let [actor (when actor-in-hash actor)        
        exception-content? (= content-type "application/x-www-form-urlencoded")
        end-str (str current-timestamp actor)
        url (URL. url)
        host (.getHost url)
        request-uri (.getPath url)        
        item-to-encode (cond
                         (empty? request-body) (str url end-str)

                         (exception-content?)
                         (str (clojure.string/upper-case http-method) "\n"
                              host "\n"
                              request-uri "\n"
                              end-str)
                         
                         :default (str request-body end-str))] ;; when no request-body]
    (make-sha512-hmac shared-secret item-to-encode )))

(defn get-nonce
  "Retrieve the body of the nonce, which will contain a key and a value"
  [api-key actor]
  (let [actor (if (empty? actor)
                ""
                (str "/" actor))
        uri (str "https://ws.byu.edu/authentication/services/rest/v1/hmac/nonce/" api-key actor)
        nonce (client/post uri)]
    (json/parse-string (:body nonce))))

(defn nonce-encode [shared-secret nonce-value]
  (make-sha512-hmac shared-secret nonce-value))

(defn get-http-authorization-header
  "Get the authorization header necessary for use of some BYU web services. See
  https://byuapi.atlassian.net/wiki/display/OITCoreDeveloperResources/Web+Service+using+Nonce-Encoded+HMAC+Signed+by+an+API+Key+Tutorial"
  [& [{:keys [api-key
              shared-secret
              key-type
              encoding-type
              url
              request-body
              actor
              content-type
              http-method
              actor-in-hash
              current-timestamp]
       :or {key-type "API"
            encoding-type "Nonce"
            url (SERVICE-URLS :records)
            request-body ""
            content-type "application/json" 
            http-method "GET"
            actor-in-hash true
            current-timestamp (.format DATE-FORMAT (new java.util.Date))}
       :as var-map}]]
  (if (VALID-KEY-TYPES key-type)
    (case encoding-type
      "URL" (let [actor_value (when-not (empty? actor) (str "," actor))
                  encoded-url (url-encode var-map)]
              (str encoding-type "-Encoded-" key-type "-Key " api-key "," encoded-url))
      "Nonce" (let [nonce-obj (get-nonce api-key actor)
                    encoded-url (nonce-encode shared-secret (get nonce-obj "nonceValue"))
                    nonce-key (get nonce-obj "nonceKey")]
                (str "Nonce-Encoded-" key-type "-Key " api-key "," nonce-key "," encoded-url)))
    (throw (Exception. (str "Invalid key-type " key-type)))))

