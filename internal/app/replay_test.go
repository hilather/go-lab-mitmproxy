package app

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestReplayValidatesAndCallsHook(t *testing.T) {
	svc, _ := mustBoot(t)
	id := insertRaw(t, svc, "app.lab")
	called := false
	svc.SetReplay(func(_ context.Context, stored *model.Flow) (*model.Flow, error) {
		called = true
		out := *stored
		out.ID = "01NEWFLOW00000000000000000"
		return &out, nil
	})
	got, err := svc.Replay(context.Background(), actor(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !called || got.ID == id {
		t.Fatalf("replay hook got=%+v called=%v", got, called)
	}
}

func TestReplayRejectsWebsocket(t *testing.T) {
	svc, _ := mustBoot(t)
	res, err := svc.Inbox().Insert(context.Background(), svc.Inbox().Epoch(), &model.Flow{
		Host: "app.lab", Method: "GET", Protocol: model.FlowProtocolWebSocket, State: model.FlowStateCompleted,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Replay(context.Background(), actor(), res.ID)
	requireCode(t, err, domainerr.CodeValidationFailed)
}

func TestReplayAllowsHTTP2Protocol(t *testing.T) {
	err := validateReplay(&model.Flow{
		Method: "GET", Protocol: model.FlowProtocolHTTP2,
	})
	if err != nil {
		t.Fatalf("h2 flows must be replayable as HTTP/1.1: %v", err)
	}
}

func TestReplayUnwired(t *testing.T) {
	svc, _ := mustBoot(t)
	id := insertRaw(t, svc, "app.lab")
	_, err := svc.Replay(context.Background(), actor(), id)
	requireCode(t, err, domainerr.CodeInternalError)
}
