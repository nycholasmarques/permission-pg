package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

const (
	dbUser       = "admin"
	dbPassword   = "admin"
	dbName       = "testdb"
	dbHost       = "localhost"
	dbPort       = "5432"
	monitorUser  = "monitorado"
	interval     = 10 * time.Second
	stateFile    = "permissions_state.json"
)

var previousPermissions = make(map[string]bool)

func main() {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Erro ao conectar ao banco: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Erro ao conectar ao banco (Ping): %v", err)
	}

	log.Println("Conectado ao PostgreSQL com sucesso!")


	loadState()

	for {
		checkPermissions(db)
		time.Sleep(interval)
	}
}

func checkPermissions(db *sql.DB) {

	tableQuery := `
		SELECT grantee, privilege_type, table_schema, table_name
		FROM information_schema.role_table_grants
		WHERE grantee = $1;
	`

	schemaQuery := `
		SELECT grantee, privilege_type, object_schema
		FROM information_schema.usage_privileges
		WHERE grantee = $1;
	`

	databaseQuery := `
		SELECT rolname, datname
		FROM pg_roles, pg_database
		WHERE rolname = $1 AND has_database_privilege(rolname, datname, 'CONNECT');
	`

	currentPermissions := make(map[string]bool)

	rows, err := db.Query(tableQuery, monitorUser)
	if err != nil {
		log.Printf("Erro ao obter permissões de tabelas: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var grantee, privilege, schema, table string
		if err := rows.Scan(&grantee, &privilege, &schema, &table); err != nil {
			log.Printf("Erro ao escanear resultado (tabelas): %v", err)
			return
		}

		key := fmt.Sprintf("TABLE:%s:%s:%s:%s", grantee, privilege, schema, table)
		currentPermissions[key] = true
	}

	rows, err = db.Query(schemaQuery, monitorUser)
	if err != nil {
		log.Printf("Erro ao obter permissões de esquemas: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var grantee, privilege, schema string
		if err := rows.Scan(&grantee, &privilege, &schema); err != nil {
			log.Printf("Erro ao escanear resultado (esquemas): %v", err)
			return
		}

		key := fmt.Sprintf("SCHEMA:%s:%s:%s", grantee, privilege, schema)
		currentPermissions[key] = true
	}

	rows, err = db.Query(databaseQuery, monitorUser)
	if err != nil {
		log.Printf("Erro ao obter permissões de bancos de dados: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var rolname, datname string
		if err := rows.Scan(&rolname, &datname); err != nil {
			log.Printf("Erro ao escanear resultado (bancos de dados): %v", err)
			return
		}

		key := fmt.Sprintf("DATABASE:%s:CONNECT:%s", rolname, datname)
		currentPermissions[key] = true
	}

	if len(previousPermissions) > 0 {
		changes := detectChanges(previousPermissions, currentPermissions)
		if len(changes) > 0 {
			log.Printf("Mudanças detectadas: %s", strings.Join(changes, ", "))
		}
	} else {
		log.Println("Iniciando monitoramento...")
	}

	previousPermissions = make(map[string]bool)
	for k, v := range currentPermissions {
		previousPermissions[k] = v
	}

	saveState()
}

func detectChanges(old, new map[string]bool) []string {
	var changes []string

	for perm := range new {
		if !old[perm] {
			changes = append(changes, "ADICIONADO: "+perm)
		}
	}

	for perm := range old {
		if !new[perm] {
			changes = append(changes, "REMOVIDO: "+perm)
		}
	}

	return changes
}

// Salva o estado atual em um arquivo JSON
func saveState() {
	file, err := json.MarshalIndent(previousPermissions, "", "  ")
	if err != nil {
		log.Printf("Erro ao serializar estado: %v", err)
		return
	}

	err = os.WriteFile(stateFile, file, 0644)
	if err != nil {
		log.Printf("Erro ao salvar estado no arquivo: %v", err)
	}
}

// Carrega o estado anterior de um arquivo JSON
func loadState() {
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		log.Println("Nenhum estado anterior encontrado. Iniciando do zero.")
		return
	}

	file, err := os.ReadFile(stateFile)
	if err != nil {
		log.Printf("Erro ao ler arquivo de estado: %v", err)
		return
	}

	err = json.Unmarshal(file, &previousPermissions)
	if err != nil {
		log.Printf("Erro ao deserializar estado: %v", err)
		return
	}

	log.Println("Estado anterior carregado com sucesso.")
}