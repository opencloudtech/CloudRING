// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package transactionalstate

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// VerifyApplicationIdentity checks effective login privileges and the migrated
// schema using the application's own connection. A DSN username alone does not
// establish that a serving process lacks migration or superuser privileges.
// This read-only check never executes migrations or needs the owner's secret.
func (store *Store) VerifyApplicationIdentity(ctx context.Context, ownerRole, applicationRole string) error {
	if store == nil || store.pool == nil || ctx == nil {
		return errors.New("application database identity is unavailable")
	}
	if _, _, err := migrationRoles(Config{MigrationOwnerRole: ownerRole, ApplicationRole: applicationRole}); err != nil {
		return errors.New("application database identity is invalid")
	}
	bounded, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	tx, err := store.pool.BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return errors.New("read application database identity")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var currentUser, databaseOwner string
	var databaseCreate bool
	if err := tx.QueryRow(bounded, `
		SELECT current_user, pg_get_userbyid(datdba), has_database_privilege(current_user, current_database(), 'CREATE')
		FROM pg_database
		WHERE datname = current_database()
	`).Scan(&currentUser, &databaseOwner, &databaseCreate); err != nil || currentUser != applicationRole || databaseOwner != ownerRole || databaseCreate {
		return errors.New("application database identity is invalid")
	}
	if err := verifyApplicationRole(bounded, tx, applicationRole); err != nil {
		return err
	}
	versions := expectedMigrationRecords()
	if len(versions) == 0 {
		return errors.New("application database schema is unavailable")
	}
	if err := verifyMigrationContract(bounded, tx, ownerRole, applicationRole, versions[len(versions)-1].Version); err != nil {
		return err
	}
	if err := tx.Commit(bounded); err != nil {
		return errors.New("verify application database identity")
	}
	return nil
}
