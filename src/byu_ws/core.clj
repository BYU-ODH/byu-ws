(ns byu-ws.core
  (:require [clj-http.client :as client]
            [ring.util.codec :as r]
            [cheshire.core :as json])
  (:import [java.net URL]
           [org.apache.commons.codec.binary Hex]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(defonce AUTH-URL "https://ws.byu.edu/authentication/services/rest/v1/provider/URL-Encoded-API-Key/validate")

(defonce VALID-KEY-TYPES #{"API" "WsSession"})

(defonce DATE-FORMAT (java.text.SimpleDateFormat. "YYYY-MM-dd HH:mm:ss"))

(defonce SERVICE-URLS {:records "https://api.byu.edu/rest/v1/apikey/academic/records/studentrecord/"
                       :schedule "https://ws.byu.edu/rest/v1.0/academic/registration/studentschedule/"})

(defn make-sha512-hmac [shared-secret item-to-encode]
  ;; base code from Node.js
  ;; better instructions: https://byuapi.atlassian.net/wiki/display/OITCoreDeveloperResources/Web+Service+using+Nonce-Encoded+HMAC+Signed+by+an+API+Key+Tutorial
  (let [algorithm "HmacSHA512"
        key-spec (SecretKeySpec. (.getBytes shared-secret "UTF8") algorithm)
        mac (Mac/getInstance (.getAlgorithm key-spec))
        _ (.init mac key-spec)
        encoder (new org.apache.commons.codec.binary.Base64 0)
        ]
    (-> item-to-encode
        (.getBytes "UTF8")
        (->> (.doFinal mac)
             (.encodeToString encoder)))
    ;; (->> item-to-encode .getBytes (.doFinal mac) Hex/encodeHexString
    ;;      ) ;; ?? Might need to be base 64 directly, not hexString first
    ))

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

                         (exception-content?) ;; split the url and insert the first and second elements
                         (str (clojure.string/upper-case http-method) "\n"
                              host "\n"
                              request-uri "\n"
                                        ;(sort-params request-body) ;; TODO sort-params? Why?
                              end-str)
                         
                         :default (str request-body end-str))] ;; when no request-body]
    ;; return val
    (->> item-to-encode (make-sha512-hmac shared-secret) ;; remember: changing the var order from the js
         r/base64-encode)))

(defn get-nonce [api-key actor]
  (let [actor (if (empty? actor)
                ""
                (str "/" actor))
        uri (str "https://ws.byu.edu/authentication/services/rest/v1/hmac/nonce/" api-key actor)
        nonce (client/post uri)]
    (json/parse-string (:body nonce))))

(defn nonce-encode [shared-secret nonce-value]
  (make-sha512-hmac shared-secret nonce-value))
  ;; (-> (make-sha512-hmac shared-secret nonce-value)
  ;;     (.getBytes)
  ;;     r/base64-encode))

(defn get-http-authorization-header
  "Get the authorization header necessary for use of some BYU web services"
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
       :or { ;; Grants or humanities keys? We'll start with grants. 
            api-key "Ovo1FxW0yAz7-HNbdnM9"
            shared-secret "hziQkSgRpdZla_giFfCK4h_OT98ykZM4ZYfoERvB"
            key-type "API"
            encoding-type "Nonce"
            url (service-urls :records)
            request-body ""
            actor "torysa" ;; netid
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



(defn get-student-data [&[{:keys [service param netid]
                           :or {service :records
                                param "081270232" ;; TODO, IS NOT THE BYU ID#. get from person info (cas login?)
                                netid "torysa" ;; TODO
                                }}]]
  (let [service-url (str (SERVICE-URLS service) param) ;; year necessary?
        auth-header (get-http-authorization-header {; :api-key ;TODO get from env?
                                        ; :shared-secret ;TODO get from env?
                                                    :key-type "API" ;; Unnecessary
                                                    :encoding-type "Nonce"
                                                    :url service-url
                                                    :request-body ""
                                        ; :actor "torysa" ;; TODO from CAS
                                                    :content-type "application/json"
                                                    :http-method "GET"
                                                    :actor-in-hash true
                                                    })]
    (client/get service-url {:headers {:authorization auth-header}})))