package cast

import (
	"encoding/binary"
	"fmt"
	"io"

	pb "cast-receiver/castpb"

	"google.golang.org/protobuf/proto"
)

// ReadMessage reads a length-prefixed CastMessage from r.
func ReadMessage(r io.Reader) (*pb.CastMessage, error) {
	var len uint32
	if err := binary.Read(r, binary.BigEndian, &len); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if len > 1<<20 { // 1 MB sanity limit
		return nil, fmt.Errorf("message too large: %d", len)
	}
	buf := make([]byte, len)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	msg := &pb.CastMessage{}
	if err := proto.Unmarshal(buf, msg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return msg, nil
}

// WriteMessage writes a length-prefixed CastMessage to w.
func WriteMessage(w io.Writer, msg *pb.CastMessage) error {
	buf, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(buf)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}
