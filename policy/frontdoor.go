package policy

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"

	"github.com/jonhadfield/azwaf/logging"
	"github.com/jonhadfield/azwaf/session"
)

func ListFrontDoors(subID string) error {
	s, err := session.New()
	if err != nil {
		return err
	}

	frontDoors, err := GetFrontDoors(s, subID)
	if err != nil {
		return err
	}

	if len(frontDoors) == 0 {
		logging.Info("no front doors found")

		return nil
	}

	showFrontDoors(frontDoors)

	return nil
}

func GetFrontDoorIDs(s *session.Session, subID string) (ids []string, err error) {
	// get all front door ids
	_, err = s.GetFrontDoorsClient(subID)
	if err != nil {
		return
	}

	ctx := context.Background()

	fetchMax := int32(MaxFrontDoorsToFetch)

	pager := s.FrontDoorsClients[subID].NewListPager(nil)

	var total int

	for pager.More() {
		var page armfrontdoor.FrontDoorsClientListResponse

		page, err = pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to advance page of front doors - %w", err)
		}

		for _, resource := range page.Value {
			ids = append(ids, *resource.ID)

			total++

			if total == int(fetchMax) {
				return
			}
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

		logging.Debugf("requesting front door id %s", frontDoorID)

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
