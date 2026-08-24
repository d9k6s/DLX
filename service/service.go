/*
 * @Author: Vincent Yang
 * @Date: 2023-07-01 21:45:34
 * @LastEditors: Jason Lyu
 * @LastEditTime: 2025-04-08 13:45:00
 * @FilePath: /DLX/service/service.go
 * @Telegram: https://t.me/missuo
 * @GitHub: https://github.com/missuo
 *
 * Copyright © 2024 by Vincent, All Rights Reserved.
 */

package service

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/OwO-Network/DLX/translate"
)

func authMiddleware(cfg *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.Token != "" {
			providedTokenInQuery := c.Query("token")
			providedTokenInHeader := authorizationToken(c.GetHeader("Authorization"))

			if providedTokenInHeader != cfg.Token && providedTokenInQuery != cfg.Token {
				c.JSON(http.StatusUnauthorized, gin.H{
					"code":    http.StatusUnauthorized,
					"message": "Invalid access token",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func authorizationToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 ||
		(!strings.EqualFold(parts[0], "Bearer") && !strings.EqualFold(parts[0], "DeepL-Auth-Key")) {
		return ""
	}
	return parts[1]
}

type PayloadFree struct {
	TransText   string `json:"text"`
	SourceLang  string `json:"source_lang"`
	TargetLang  string `json:"target_lang"`
	TagHandling string `json:"tag_handling"`
}

type PayloadAPI struct {
	Text        []string `json:"text"`
	TargetLang  string   `json:"target_lang"`
	SourceLang  string   `json:"source_lang"`
	TagHandling string   `json:"tag_handling"`
}

// hasProAccessToken only checks whether credentials were provided. Token
// format, expiry, audience, and account entitlement are validated upstream.
// OAuth access tokens may be JWTs and therefore contain dots.
func hasProAccessToken(token string) bool {
	return token != ""
}

func proAccessTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("dl_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func redactSensitiveQuery(path string) string {
	queryStart := strings.IndexByte(path, '?')
	if queryStart < 0 {
		return path
	}

	query, err := url.ParseQuery(path[queryStart+1:])
	if err != nil {
		return path[:queryStart] + "?[REDACTED]"
	}
	for key := range query {
		if strings.EqualFold(key, "token") {
			query.Set(key, "REDACTED")
		}
	}
	return path[:queryStart] + "?" + query.Encode()
}

func safeGinLogFormatter(param gin.LogFormatterParams) string {
	return fmt.Sprintf(
		"[GIN] %v | %3d | %13v | %15s | %-7s %s%s\n",
		param.TimeStamp.Format("2006/01/02 - 15:04:05"),
		param.StatusCode,
		param.Latency,
		param.ClientIP,
		param.Method,
		redactSensitiveQuery(param.Path),
		param.ErrorMessage,
	)
}

func translationClientModeLog(profile translate.ClientProfile) string {
	mode := "iOS"
	if profile == translate.ClientProfileChrome {
		mode = "Chrome"
	}

	return fmt.Sprintf("[DLX] translation client mode is %s (DL_CLIENT_PROFILE=%s).", mode, profile)
}

func Router(cfg *Config) *gin.Engine {
	if cfg.Token != "" {
		fmt.Println("[DLX API] access token protection is enabled.")
	}

	clientProfile, clientProfileErr := translate.ParseClientProfile(cfg.DlClientProfile)
	if clientProfileErr != nil {
		log.Printf("[DeepL] %v; falling back to the iOS client profile.", clientProfileErr)
		clientProfile = translate.ClientProfileIOS
	}
	log.Print(translationClientModeLog(clientProfile))

	proTokens, proTokenInitErr := newProTokenManager(cfg)
	if proTokenInitErr != nil {
		log.Printf("Failed to load DeepL OAuth token state: %v", proTokenInitErr)
	} else {
		proTokens.logConfiguration()
		if proTokens.canRefresh() && cfg.DlTokenStore == "" {
			log.Println("[DeepL OAuth] warning: DL_TOKEN_STORE is not configured; rotated tokens will not survive a restart.")
		}
	}

	r := gin.New()
	r.Use(gin.LoggerWithFormatter(safeGinLogFormatter), gin.Recovery())
	r.Use(cors.Default())

	// Defining the root endpoint which returns the project details
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code":    http.StatusOK,
			"message": "DLX Translation API, Developed by sjlleo and missuo. Go to /translate with POST. https://github.com/OwO-Network/DLX",
		})
	})

	// Free API endpoint, No Pro Account required
	r.POST("/translate", authMiddleware(cfg), func(c *gin.Context) {
		req := PayloadFree{}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "Invalid request payload",
			})
			return
		}

		sourceLang := req.SourceLang
		targetLang := req.TargetLang
		translateText := req.TransText
		tagHandling := req.TagHandling

		proxyURL := cfg.Proxy

		if tagHandling != "" && tagHandling != "html" && tagHandling != "xml" {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "Invalid tag_handling value. Allowed values are 'html' and 'xml'.",
			})
			return
		}

		result, err := translate.TranslateByDLXContextWithProfile(c.Request.Context(), sourceLang, targetLang, translateText, tagHandling, proxyURL, "", clientProfile)
		if err != nil {
			log.Printf("Translation failed: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": "Translation failed",
			})
			return
		}

		if result.Code == http.StatusOK {
			c.JSON(http.StatusOK, gin.H{
				"code":         http.StatusOK,
				"id":           result.ID,
				"data":         result.Data,
				"alternatives": result.Alternatives,
				"source_lang":  result.SourceLang,
				"target_lang":  result.TargetLang,
				"method":       result.Method,
			})
		} else {
			c.JSON(result.Code, gin.H{
				"code":    result.Code,
				"message": result.Message,
			})

		}
	})

	// Pro API endpoint, Pro Account required
	r.POST("/v1/translate", authMiddleware(cfg), func(c *gin.Context) {
		req := PayloadFree{}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "Invalid request payload",
			})
			return
		}

		sourceLang := req.SourceLang
		targetLang := req.TargetLang
		translateText := req.TransText
		tagHandling := req.TagHandling
		proxyURL := cfg.Proxy

		if tagHandling != "" && tagHandling != "html" && tagHandling != "xml" {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "Invalid tag_handling value. Allowed values are 'html' and 'xml'.",
			})
			return
		}

		cookieToken := proAccessTokenFromCookie(c.Request)

		if proTokenInitErr != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"code":    http.StatusServiceUnavailable,
				"message": "DeepL Pro authentication state could not be loaded",
			})
			return
		}

		dlSession := cookieToken
		if dlSession == "" {
			var err error
			dlSession, err = proTokens.getAccessToken(c.Request.Context())
			if err != nil && !errors.Is(err, errNoProCredentials) {
				status, message := proTokenFailure(err)
				c.JSON(status, gin.H{"code": status, "message": message})
				return
			}
		}

		if !hasProAccessToken(dlSession) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "No dl_session Found",
			})
			return
		}

		translateWithToken := func(token string) (translate.DLXTranslationResult, error) {
			return translate.TranslateByDLXContextWithProfile(c.Request.Context(), sourceLang, targetLang, translateText, tagHandling, proxyURL, token, clientProfile)
		}
		result, err := translateWithToken(dlSession)
		if err != nil {
			log.Printf("Translation failed: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": "Translation failed",
			})
			return
		}

		if result.Code == http.StatusUnauthorized && cookieToken == "" && proTokens.canRefresh() {
			refreshedToken, refreshErr := proTokens.refreshAfterUnauthorized(c.Request.Context(), dlSession)
			if refreshErr != nil {
				status, message := proTokenFailure(refreshErr)
				c.JSON(status, gin.H{"code": status, "message": message})
				return
			}
			result, err = translateWithToken(refreshedToken)
			if err != nil {
				log.Printf("Translation failed after DeepL OAuth refresh: %s", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"code":    http.StatusInternalServerError,
					"message": "Translation failed",
				})
				return
			}
		}

		if result.Code == http.StatusOK {
			c.JSON(http.StatusOK, gin.H{
				"code":         http.StatusOK,
				"id":           result.ID,
				"data":         result.Data,
				"alternatives": result.Alternatives,
				"source_lang":  result.SourceLang,
				"target_lang":  result.TargetLang,
				"method":       result.Method,
			})
		} else {
			c.JSON(result.Code, gin.H{
				"code":    result.Code,
				"message": result.Message,
			})

		}
	})

	// Free API endpoint, Consistent with the official API format
	r.POST("/v2/translate", authMiddleware(cfg), func(c *gin.Context) {
		proxyURL := cfg.Proxy

		var translateText string
		var targetLang string

		translateText = c.PostForm("text")
		targetLang = c.PostForm("target_lang")

		if translateText == "" || targetLang == "" {
			var jsonData struct {
				Text       []string `json:"text"`
				TargetLang string   `json:"target_lang"`
			}

			if err := c.ShouldBindJSON(&jsonData); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": "Invalid request payload",
				})
				return
			}

			translateText = strings.Join(jsonData.Text, "\n")
			targetLang = jsonData.TargetLang
		}

		result, err := translate.TranslateByDLXContextWithProfile(c.Request.Context(), "", targetLang, translateText, "", proxyURL, "", clientProfile)
		if err != nil {
			log.Printf("Translation failed: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": "Translation failed",
			})
			return
		}

		if result.Code == http.StatusOK {
			c.JSON(http.StatusOK, gin.H{
				"translations": []map[string]interface{}{
					{
						"detected_source_language": result.SourceLang,
						"text":                     result.Data,
					},
				},
			})
		} else {
			c.JSON(result.Code, gin.H{
				"code":    result.Code,
				"message": result.Message,
			})
		}
	})

	// Catch-all route to handle undefined paths
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    http.StatusNotFound,
			"message": "Path not found",
		})
	})

	return r
}
