/*
 * @Author: Vincent Yang
 * @Date: 2023-07-01 21:45:34
 * @LastEditors: Jason Lyu
 * @LastEditTime: 2025-04-08 13:45:00
 * @FilePath: /DLX/main.go
 * @Telegram: https://t.me/missuo
 * @GitHub: https://github.com/missuo
 *
 * Copyright © 2024 by Vincent, All Rights Reserved.
 */

package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"

	"github.com/OwO-Network/DLX/service"
)

func main() {
	cfg := service.InitConfig()

	fmt.Printf("DLX has been successfully launched! Listening on %v:%v\n", cfg.IP, cfg.Port)
	fmt.Println("Developed by sjlleo <i@leo.moe> and missuo <me@missuo.me>.")

	// Setting the application to release mode
	gin.SetMode(gin.ReleaseMode)

	app := service.Router(cfg)
	if err := app.Run(fmt.Sprintf("%v:%v", cfg.IP, cfg.Port)); err != nil {
		log.Fatalf("DLX server stopped: %v", err)
	}
}
