package config

const (
	// ResourceIDComponents is the expected number of components in a resource ID
	ResourceIDComponents = 9

	// SubscriptionIDLengthShort and SubscriptionIDLengthLong represent the two
	// allowed lengths for subscription IDs.
	SubscriptionIDLengthShort = 36
	SubscriptionIDLengthLong  = 38
)

// SubscriptionIDHyphenPositions defines where hyphens should appear in a
// subscription ID.
var SubscriptionIDHyphenPositions = []int{8, 13, 18, 23}
