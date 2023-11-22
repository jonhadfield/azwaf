package policy

import (
	"context"
	"fmt"
	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
)

func ListFrontDoors(subID string) error {
	s := session.New()

	frontDoors, err := GetFrontDoors(s, subID)
	if err != nil {
		return err
	}

	if len(frontDoors) == 0 {
		fmt.Println("no front doors found")

		return nil
	}

	showFrontDoors(frontDoors)

	return nil
}

func GetFrontDoorIDs(s *session.Session, subID string) (ids []string, err error) {
	// get all front door ids
	err = s.GetResourcesClient(subID)
	if err != nil {
		return
	}

	ctx := context.Background()

	fetchMax := int32(MaxFrontDoorsToFetch)

	it, merr := s.ResourcesClients[subID].ListComplete(ctx, "resourceType eq 'Microsoft.Network/frontdoors'", "", &fetchMax)
	if merr != nil {
		return nil, fmt.Errorf(merr.Error(), GetFunctionName())
	}

	for it.NotDone() {
		if it.Value().ID == nil {
			panic("unexpected front door with nil id returned")
		}

		ids = append(ids, *it.Value().ID)

		merr = it.NextWithContext(ctx)
		if merr != nil {
			return nil, fmt.Errorf(merr.Error(), GetFunctionName())
		}
	}

	return
}

func GetFrontDoors(s *session.Session, subID string) (frontDoors FrontDoors, err error) {
	frontDoorIDs, err := GetFrontDoorIDs(s, subID)
	if err != nil || len(frontDoorIDs) == 0 {
		return
	}

	_, err = s.GetFrontDoorsClient(subID)
	if err != nil {
		return
	}

	err = s.GetFrontDoorPoliciesClient(subID)
	if err != nil {
		return
	}

	// get all front doors by id
	for _, frontDoorID := range frontDoorIDs {
		var fd FrontDoor

		logrus.Debugf("requesting front door id %s", frontDoorID)

		fd, err = GetFrontDoorByID(s, frontDoorID)
		if err != nil {
			return
		}

		frontDoors = append(frontDoors, FrontDoor{
			name:      fd.name,
			endpoints: fd.endpoints,
		})
	}

	return
}
