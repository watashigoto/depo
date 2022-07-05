package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"

	"github.com/joho/godotenv"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/swaggo/gin-swagger/swaggerFiles"
	"golang.org/x/crypto/bcrypt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	_ "depo/docs"
)

// @title Swagger
// @version 1.0
// @description Api Documentation
// @securityDefinitions.apikey JWTAuth
// @in header
// @name Authorization

type Server struct {
	db   *gorm.DB
	http *gin.Engine
}

var svr Server

func main() {
	if err := godotenv.Load(".env"); err != nil {
		panic("cannot load env")
	}

	initDatabase()
	runHttpServer()
}

func initDatabase() {
	db_host := os.Getenv("DB_HOST")
	db_port := os.Getenv("DB_PORT")
	db_user := os.Getenv("DB_USER")
	db_pass := os.Getenv("DB_PASSWORD")
	db_name := os.Getenv("DB_NAME")

	connectString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", db_user, db_pass, db_host, db_port, db_name)
	db, err := gorm.Open(mysql.Open(connectString), &gorm.Config{})

	if err != nil {
		panic("failed to connect database")
	}

	if err != nil {
		log.Fatal(err)
		return
	}

	svr.db = db
	db.AutoMigrate(&Users{}, &Customers{}, &Orders{})
}

func runHttpServer() {
	router := gin.Default()
	svr.http = router

	//api doc http://localhost/swagger/index.html
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.POST("/user_register", UserRegister)
	router.POST("/user_login", UserLogin)

	auth := router.Group("/").Use(AuthMiddleware())
	{
		auth.GET("/customers", handleGetCustomers)
		auth.GET("/customers/:id", handleGetCustomerDetail)
		auth.POST("/customers", handleAddCustomers)
		auth.PUT("/customers/:id", handleUpdateCustomers)
		auth.DELETE("/customers/:id", handleDeleteCustomers)

		auth.GET("/orders", handleGetOrders)
		auth.GET("/orders/:id", handleGetOrderDetail)
		auth.POST("/orders", handleAddOrders)
		auth.PUT("/orders/:id", handleUpdateOrders)
		auth.DELETE("/orders/:id", handleDeleteOrders)
	}

	router.Run(":" + os.Getenv("WEBSITE_PORT"))
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(401, gin.H{"error": "request does not contain an access token"})
			c.Abort()
			return
		}
		err := ValidateToken(tokenString)
		if err != nil {
			c.JSON(401, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.Next()
	}
}

type Users struct {
	gorm.Model `swaggerignore:"true"`
	Username   string `gorm:"index:idx_username,unique"`
	Password   string
}

type UserOutputs struct {
	ID       uint
	Username string
	Token    string
}

type Customers struct {
	gorm.Model    `swaggerignore:"true"`
	IDUserCreator int
	Name          string
	Orders        []Orders `gorm:"foreignKey:IDCustomer;references:ID" swaggerignore:"true"`
	UserCreator   *Users   `gorm:"foreignKey:IDUserCreator;references:ID" swaggerignore:"true"`
}

type Orders struct {
	gorm.Model    `swaggerignore:"true"`
	IDCustomer    int
	IDUserCreator int
	Name          string
	Customer      *Customers `gorm:"foreignKey:IDCustomer;references:ID" swaggerignore:"true"`
	UserCreator   *Users     `gorm:"foreignKey:IDUserCreator;references:ID" swaggerignore:"true"`
}

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func ResponseJSON(c *gin.Context, httpCode, errCode int, message string, data interface{}) {
	c.JSON(httpCode, Response{
		Code:    errCode,
		Message: message,
		Data:    data,
	})
}

func BindAndValid(c *gin.Context, form interface{}) (int, int) {
	err := c.Bind(form)
	if err != nil {
		return http.StatusBadRequest, 400
	}

	return http.StatusOK, 200
}

// UserRegister godoc
// @Summary user login
// @tags Auth
// @Accept  json
// @Produce  json
// @Param Users body Users true "Users"
// @Success 200 {object} OutputFormat{Data=UserOutputs}
// @Router /user_register [post]
func UserRegister(c *gin.Context) {
	var user Users
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		c.Abort()
		return
	}
	if err := user.HashPassword(user.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}
	record := svr.db.Create(&user)
	if record.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": record.Error.Error()})
		c.Abort()
		return
	}

	userOutput := UserOutputs{
		ID:       user.ID,
		Username: user.Username,
	}

	ResponseJSON(c, http.StatusOK, 200, "", userOutput)
}

// UserLogin godoc
// @Summary user login
// @tags Auth
// @Accept  json
// @Produce  json
// @Param Users body Users true "Users"
// @Success 200 {object} OutputFormat{Data=UserOutputs}
// @Router /user_login [post]
func UserLogin(c *gin.Context) {
	var request Users
	var user Users

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	record := svr.db.Where("username = ?", request.Username).First(&user)
	if record.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": record.Error.Error()})
		c.Abort()
		return
	}
	credentialError := user.CheckPassword(request.Password)
	if credentialError != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		c.Abort()
		return
	}

	tokenString, err := GenerateJWT(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	userOutput := UserOutputs{
		ID:       user.ID,
		Username: user.Username,
		Token:    tokenString,
	}

	ResponseJSON(c, http.StatusOK, 200, "", userOutput)
}

// handleGetCustomers godoc
// @Summary get customers
// @tags Customers
// @Accept  json
// @Produce  json
// @Param name query string false "name"
// @Param page query string false "1"
// @Param limit query string false "20"
// @Param order query string false "id DESC"
// @Success 200 {object} OutputFormat{Data=Paginator{Records=[]Customers}}
// @Security JWTAuth
// @Router /customers [get]
func handleGetCustomers(c *gin.Context) {
	name := c.DefaultQuery("name", "")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	order := c.DefaultQuery("order", "id DESC")

	var output []Customers

	query := svr.db.Preload("Orders").Preload("UserCreator")

	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}

	query = query.Find(&output)

	paginator := Paging(&PaginationParam{
		DB:      query,
		Page:    page,
		Limit:   limit,
		OrderBy: []string{order},
		ShowSQL: true,
	}, &output)

	ResponseJSON(c, http.StatusOK, 200, "", paginator)
}

// GetBuckets godoc
// @Summary get customer detail
// @tags Customers
// @Accept  json
// @Produce  json
// @Param id path int true "1"
// @Success 200 {object} OutputFormat{Data=Customers}
// @Security JWTAuth
// @Router /customers/{id} [get]
func handleGetCustomerDetail(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var output Customers

	if err := svr.db.Preload("Orders").Preload("UserCreator").First(&output, id).Error; err != nil {
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), nil)
		return
	}

	ResponseJSON(c, http.StatusOK, 200, "", output)
}

// handleAddCustomers godoc
// @Summary add customer
// @tags Customers
// @Accept  json
// @Produce  json
// @Param Customers body Customers true "Customers"
// @Success 200 {object} OutputFormat{Data=Customers}
// @Security JWTAuth
// @Router /customers [post]
func handleAddCustomers(c *gin.Context) {
	var param Customers

	httpCode, errCode := BindAndValid(c, &param)
	if errCode != 200 {
		ResponseJSON(c, httpCode, errCode, "invalid param", nil)
		return
	}

	tx := svr.db.Begin()

	if err := tx.Create(&param).Error; err != nil {
		tx.Rollback()
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), nil)
		return
	}

	tx.Commit()

	ResponseJSON(c, http.StatusOK, 200, "", param)
}

// handleUpdateCustomers godoc
// @Summary update customer
// @tags Customers
// @Accept json
// @Produce  json
// @Param id path int true "1"
// @Param Customers body Customers true "Customers"
// @Success 200 {object} OutputFormat{Data=Customers}
// @Security JWTAuth
// @Router /customers/{id} [put]
func handleUpdateCustomers(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var param Customers

	httpCode, errCode := BindAndValid(c, &param)
	if errCode != 200 {
		ResponseJSON(c, httpCode, errCode, "invalid param", nil)
		return
	}

	tx := svr.db.Begin()

	if err := tx.Where("id = ?", id).Updates(&param).First(&param, id).Error; err != nil {
		tx.Rollback()
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), nil)
		return
	}

	tx.Commit()

	ResponseJSON(c, http.StatusOK, 200, "", param)
}

// handleDeleteCustomers godoc
// @Summary delete customer
// @tags Customers
// @Accept  json
// @Produce  json
// @Param id path int true "1"
// @Success 200 {object} OutputFormat{Data=bool}
// @Security JWTAuth
// @Router /customers/{id} [delete]
func handleDeleteCustomers(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var param Customers

	tx := svr.db.Begin()

	if err := tx.First(&param, id).Delete(&param).Error; err != nil {
		tx.Rollback()
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), false)
		return
	}

	tx.Commit()

	ResponseJSON(c, http.StatusOK, 200, "", true)
}

// handleGetOrders godoc
// @Summary get orders
// @tags Orders
// @Accept  json
// @Produce  json
// @Param name query string false "name"
// @Param id_customer query string false "1"
// @Param page query string false "1"
// @Param limit query string false "20"
// @Param order query string false "id DESC"
// @Success 200 {object} OutputFormat{Data=Paginator{Records=[]Orders}}
// @Security JWTAuth
// @Router /orders [get]
func handleGetOrders(c *gin.Context) {
	name := c.DefaultQuery("name", "")
	id_customer := c.DefaultQuery("id_customer", "")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	order := c.DefaultQuery("order", "id DESC")

	var output []Orders

	query := svr.db.Preload("Customer.UserCreator").Preload("UserCreator")

	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}

	if id_customer != "" {
		query = query.Where("id_customer = ?", id_customer)
	}

	query = query.Find(&output)

	paginator := Paging(&PaginationParam{
		DB:      query,
		Page:    page,
		Limit:   limit,
		OrderBy: []string{order},
		ShowSQL: true,
	}, &output)

	ResponseJSON(c, http.StatusOK, 200, "", paginator)
}

// handleGetOrderDetail godoc
// @Summary get order detail
// @tags Orders
// @Accept  json
// @Produce  json
// @Param id path int true "1"
// @Success 200 {object} OutputFormat{Data=Orders}
// @Security JWTAuth
// @Router /orders/{id} [get]
func handleGetOrderDetail(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var output Orders

	if err := svr.db.Preload("Customer.UserCreator").Preload("UserCreator").First(&output, id).Error; err != nil {
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), nil)
		return
	}

	ResponseJSON(c, http.StatusOK, 200, "", output)
}

// handleAddOrders godoc
// @Summary add order
// @tags Orders
// @Accept  json
// @Produce  json
// @Param Orders body Orders true "Orders"
// @Success 200 {object} OutputFormat{Data=Orders}
// @Security JWTAuth
// @Router /orders [post]
func handleAddOrders(c *gin.Context) {
	var param Orders

	httpCode, errCode := BindAndValid(c, &param)
	if errCode != 200 {
		ResponseJSON(c, httpCode, errCode, "invalid param", nil)
		return
	}

	tx := svr.db.Begin()

	if err := tx.Create(&param).Error; err != nil {
		tx.Rollback()
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), nil)
		return
	}

	tx.Commit()

	ResponseJSON(c, http.StatusOK, 200, "", param)
}

// handleUpdateOrders godoc
// @Summary update order
// @tags Orders
// @Accept json
// @Produce  json
// @Param id path int true "1"
// @Param Orders body Orders true "Orders"
// @Success 200 {object} OutputFormat{Data=Orders}
// @Security JWTAuth
// @Router /orders/{id} [put]
func handleUpdateOrders(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var param Orders

	httpCode, errCode := BindAndValid(c, &param)
	if errCode != 200 {
		ResponseJSON(c, httpCode, errCode, "invalid param", nil)
		return
	}

	tx := svr.db.Begin()

	if err := tx.Where("id = ?", id).Updates(&param).First(&param, id).Error; err != nil {
		tx.Rollback()
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), nil)
		return
	}

	tx.Commit()

	ResponseJSON(c, http.StatusOK, 200, "", param)
}

// handleDeleteOrders godoc
// @Summary delete order
// @tags Orders
// @Accept  json
// @Produce  json
// @Param id path int true "1"
// @Success 200 {object} OutputFormat{Data=bool}
// @Security JWTAuth
// @Router /orders/{id} [delete]
func handleDeleteOrders(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var param Orders

	tx := svr.db.Begin()

	if err := tx.First(&param, id).Delete(&param).Error; err != nil {
		tx.Rollback()
		ResponseJSON(c, http.StatusInternalServerError, 500, err.Error(), false)
		return
	}

	tx.Commit()

	ResponseJSON(c, http.StatusOK, 200, "", true)
}

type PaginationParam struct {
	DB      *gorm.DB
	Page    int
	Limit   int
	OrderBy []string
	ShowSQL bool
}

type Paginator struct {
	TotalRecord int64
	TotalPage   int
	Records     interface{}
	Offset      int
	Limit       int
	Page        int
	PrevPage    int
	NextPage    int
}

func Paging(p *PaginationParam, result interface{}) *Paginator {
	db := p.DB

	if p.ShowSQL {
		db = db.Debug()
	}
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Limit == 0 {
		p.Limit = 10
	}

	done := make(chan bool, 1)
	var paginator Paginator
	var count int64
	var offset int

	countRecords(db, result, done, &count)

	if len(p.OrderBy) > 0 {
		for _, o := range p.OrderBy {
			db = db.Order(o)
		}
	}

	if p.Page == 1 {
		offset = 0
	} else {
		offset = (p.Page - 1) * p.Limit
	}

	db.Limit(p.Limit).Offset(offset).Find(result)

	paginator.TotalRecord = count
	paginator.Records = result
	paginator.Page = p.Page

	paginator.Offset = offset
	paginator.Limit = p.Limit
	paginator.TotalPage = int(math.Ceil(float64(count) / float64(p.Limit)))

	if p.Page > 1 {
		paginator.PrevPage = p.Page - 1
	} else {
		paginator.PrevPage = p.Page
	}

	if p.Page == paginator.TotalPage {
		paginator.NextPage = p.Page
	} else {
		paginator.NextPage = p.Page + 1
	}
	return &paginator
}

func countRecords(db *gorm.DB, anyType interface{}, done chan bool, count *int64) {
	db.Select(db.Statement.Table + ".id").Find(anyType).Count(count)
}

type OutputFormat struct {
	Success bool
	Message string
	Data    interface{}
	Errors  []struct {
		ErrorFormat
	}
	Code string
}

type ErrorFormat struct {
	Field string
	Error string
}

func ResponseFormat(success bool, message string, data interface{}, errors []struct{ ErrorFormat }) *OutputFormat {
	response := new(OutputFormat)
	response.Success = success
	response.Message = message
	response.Data = data
	response.Errors = errors

	return response
}

func ResponseFormatCode(success bool, message string, data interface{}, errors []struct{ ErrorFormat }, code string) *OutputFormat {
	response := ResponseFormat(success, message, data, errors)
	response.Code = code

	return response
}

var jwtKey = []byte("jwtkey")

func (user *Users) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	user.Password = string(bytes)
	return nil
}
func (user *Users) CheckPassword(providedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(providedPassword))
	if err != nil {
		return err
	}
	return nil
}

type JWTClaim struct {
	Username string
	jwt.StandardClaims
}

func GenerateJWT(username string) (tokenString string, err error) {
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &JWTClaim{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(jwtKey)
	return
}

func ValidateToken(signedToken string) (err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		},
	)
	if err != nil {
		return
	}
	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		err = errors.New("couldn't parse claims")
		return
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return
	}
	return
}
