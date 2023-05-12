package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	cliutil "github.com/bluesky-social/indigo/cmd/gosky/util"
	did "github.com/whyrusleeping/go-did"
	"github.com/eramus/go-plc-client"
	cli "github.com/urfave/cli/v2"
)

func main() {
	run(os.Args)
}

func run(args []string) {
	app := cli.App{
		Name:    "goplc",
		Usage:   "client CLI for working with a PLC server",
		Version: "0.1",
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "plc-host",
			Usage:   "method, hostname, and port of PDS instance",
			Value:   "https://plc.directory",
			EnvVars: []string{"PLC_HOST"},
		},
	}
	app.Commands = []*cli.Command{
		getHealthCmd,
		getDocumentCmd,
		getDocumentDataCmd,
		getOperationLogCmd,
		getLastOperationCmd,
		getAuditLogCmd,
		createDIDCmd,
		updateVerificationMethodCmd,
		updateHandleCmd,
		updatePDSCmd,
		updateRotationKeysCmd,
		setTombstoneCmd,
	}

	app.RunAndExitOnError()
}

var getHealthCmd = &cli.Command{
	Name:      "getHealth",
	Usage:     "get PLC server health",
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		cli := plc.New(host)
		health, err := cli.GetHealth(ctx)
		if err != nil {
			return err
		}

		h, err := json.MarshalIndent(health, "", "\t")
		if err != nil {
			return err
		}

		log.Println(string(h))
		return nil
	},
}

var getDocumentCmd = &cli.Command{
	Name:      "getDocument",
	Usage:     "get DID document for DID",
	ArgsUsage: `<did>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		args, err := needArgs(cctx, "did")
		if err != nil {
			return err
		}
		did := args[0]

		cli := plc.New(host)
		doc, err := cli.GetDocument(ctx, did)
		if err != nil {
			return err
		}

		d, err := json.MarshalIndent(doc, "", "\t")
		if err != nil {
			return err
		}

		log.Println(string(d))
		return nil
	},
}

var getDocumentDataCmd = &cli.Command{
	Name:      "getDocumentData",
	Usage:     "get document data for DID",
	ArgsUsage: `<did>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		args, err := needArgs(cctx, "did")
		if err != nil {
			return err
		}
		did := args[0]

		cli := plc.New(host)
		docData, err := cli.GetDocumentData(ctx, did)
		if err != nil {
			return err
		}

		dd, err := json.MarshalIndent(docData, "", "\t")
		if err != nil {
			return err
		}

		log.Println(string(dd))
		return nil
	},
}

var getOperationLogCmd = &cli.Command{
	Name:      "getOperationLog",
	Usage:     "get operation log for DID",
	ArgsUsage: `<did>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		args, err := needArgs(cctx, "did")
		if err != nil {
			return err
		}
		did := args[0]

		cli := plc.New(host)
		ops, err := cli.GetOperationLog(ctx, did)
		if err != nil {
			return err
		}

		o, err := json.MarshalIndent(ops, "", "\t")
		if err != nil {
			return err
		}

		log.Println(string(o))
		return nil
	},
}

var getLastOperationCmd = &cli.Command{
	Name:      "getLastOperation",
	Usage:     "get most recent operation for DID",
	ArgsUsage: `<did>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		args, err := needArgs(cctx, "did")
		if err != nil {
			return err
		}
		did := args[0]

		cli := plc.New(host)
		lastOp, err := cli.GetLastOperation(ctx, did)
		if err != nil {
			return err
		}

		lo, err := json.MarshalIndent(lastOp, "", "\t")
		if err != nil {
			return err
		}

		log.Println(string(lo))
		return nil
	},
}

var getAuditLogCmd = &cli.Command{
	Name:      "getAuditLog",
	Usage:     "get audit log for DID",
	ArgsUsage: `<did>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		args, err := needArgs(cctx, "did")
		if err != nil {
			return err
		}
		did := args[0]

		cli := plc.New(host)
		auditLog, err := cli.GetAuditLog(ctx, did)
		if err != nil {
			return err
		}

		al, err := json.MarshalIndent(auditLog, "", "\t")
		if err != nil {
			return err
		}

		log.Println(string(al))
		return nil
	},
}

var createDIDCmd = &cli.Command{
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "signing-key",
			Usage:   "path to JSON file with signing key info",
			Value:   "server.key",
			EnvVars: []string{"PLC_SIGNING_KEY_FILE"},
		},
		&cli.StringFlag{
			Name:    "recovery-key",
			Usage:   "path to JSON file with recovery key info",
			Value:   "",
			EnvVars: []string{"PLC_RECOVERY_KEY_FILE"},
		},
	},
	Name:      "createDID",
	Usage:     "create a new DID document",
	ArgsUsage: `<handle> <pds-host>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		args, err := needArgs(cctx, "handle", "pds-host")
		if err != nil {
			return err
		}
		handle, pdsHost := args[0], args[1]

		signingKey, err := cliutil.LoadKeyFromFile(cctx.String("signing-key"))
		if err != nil {
			return err
		}

		var recoveryKey *did.PrivKey
		if len(cctx.String("recovery-key")) != 0 {
			recoveryKey, err = cliutil.LoadKeyFromFile(cctx.String("recovery-key"))
			if err != nil {
				return err
			}
		} else {
			err = cliutil.GenerateKeyToFile(handle)
			if err != nil {
				return err
			}
	
			recoveryKey, err = cliutil.LoadKeyFromFile(handle)
			if err != nil {
				return err
			}
		}

		did, err := plc.New(host).CreateDID(ctx, signingKey, recoveryKey.Public().DID(), handle, pdsHost)
		if err != nil {
			return err
		}

		log.Println("new did:", did)
		return nil
	},
}

var updateVerificationMethodCmd = &cli.Command{
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "rotation-key",
			Usage:   "path to JSON file with rotation key info.",
			Value:   "",
			EnvVars: []string{"PLC_ROTATION_KEY_FILE"},
		},
	},
	Name:      "updateVerificationMethod",
	Usage:     "update or add verification method DID",
	ArgsUsage: `<did> <key-id> <key-did>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		rotationKey, err := cliutil.LoadKeyFromFile(cctx.String("rotation-key"))
		if err != nil {
			return err
		}

		args, err := needArgs(cctx, "did", "key-id", "key-did")
		if err != nil {
			return err
		}
		did, keyID, keyDID := args[0], args[1], args[2]

		err = plc.New(host).UpdateVerificationMethod(ctx, rotationKey, did, keyID, keyDID)
		if err != nil {
			return err
		}
		return nil
	},
}

var updateHandleCmd = &cli.Command{
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "rotation-key",
			Usage:   "path to JSON file with rotation key info.",
			Value:   "",
			EnvVars: []string{"PLC_ROTATION_KEY_FILE"},
		},
	},
	Name:      "updateHandle",
	Usage:     "update handle for DID",
	ArgsUsage: `<did> <handle>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		rotationKey, err := cliutil.LoadKeyFromFile(cctx.String("rotation-key"))
		if err != nil {
			return err
		}

		args, err := needArgs(cctx, "did", "handle")
		if err != nil {
			return err
		}
		did, handle := args[0], args[1]

		err = plc.New(host).UpdateHandle(ctx, rotationKey, did, handle)
		if err != nil {
			return err
		}
		return nil
	},
}

var updatePDSCmd = &cli.Command{
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "rotation-key",
			Usage:   "path to JSON file with rotation key info.",
			Value:   "",
			EnvVars: []string{"PLC_ROTATION_KEY_FILE"},
		},
	},
	Name:      "updatePDS",
	Usage:     "update PDS for DID",
	ArgsUsage: `<did> <pds-host>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		rotationKey, err := cliutil.LoadKeyFromFile(cctx.String("rotation-key"))
		if err != nil {
			return err
		}

		args, err := needArgs(cctx, "did", "pds-host")
		if err != nil {
			return err
		}
		did, pdsHost := args[0], args[1]

		err = plc.New(host).UpdatePDS(ctx, rotationKey, did, pdsHost)
		if err != nil {
			return err
		}
		return nil
	},
}

var updateRotationKeysCmd = &cli.Command{
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "rotation-key",
			Usage:   "path to JSON file with rotation key info.",
			Value:   "",
			EnvVars: []string{"PLC_ROTATION_KEY_FILE"},
		},
	},
	Name:      "updateRotationKeys",
	Usage:     "update rotation keys for DID",
	ArgsUsage: `<did> <rotation-key> [rotation-key] [rotation-key]`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		rotationKey, err := cliutil.LoadKeyFromFile(cctx.String("rotation-key"))
		if err != nil {
			return err
		}

		args, err := needArgs(cctx, "did")
		if err != nil {
			return err
		}
		did := args[0]

		if cctx.Args().Len() < 2 {
			cli.Exit("need atleast one rotation key", 127)
		}

		rotationKeys := cctx.Args().Tail()

		err = plc.New(host).UpdateRotationKeys(ctx, rotationKey, did, rotationKeys)
		if err != nil {
			return err
		}
		return nil
	},
}

var setTombstoneCmd = &cli.Command{
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "rotation-key",
			Usage:   "path to JSON file with rotation key info.",
			Value:   "",
			EnvVars: []string{"PLC_ROTATION_KEY_FILE"},
		},
	},
	Name:      "setTombstone",
	Usage:     "set tombstone for DID",
	ArgsUsage: `<did>`,
	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		host := cctx.String("plc-host")

		rotationKey, err := cliutil.LoadKeyFromFile(cctx.String("rotation-key"))
		if err != nil {
			return err
		}

		args, err := needArgs(cctx, "did")
		if err != nil {
			return err
		}
		did := args[0]

		err = plc.New(host).SetTombstone(ctx, rotationKey, did)
		if err != nil {
			return err
		}
		return nil
	},
}

func needArgs(cctx *cli.Context, name ...string) ([]string, error) {
	var out []string
	for i, n := range name {
		v := cctx.Args().Get(i)
		if v == "" {
			return nil, cli.Exit(fmt.Sprintf("argument %q required at position %d", n, i+1), 127)
		}
		out = append(out, v)
	}
	return out, nil
}
