package auth

import "testing"

func TestAuthorizeRespectsSurfaceAndZoneIdentity(t *testing.T) {
	t.Parallel()
	principal := Principal{
		Surface: SurfaceWeb,
		Grants: []Grant{
			{Permission: PermissionZonesRead, Surface: SurfaceWeb, ResourceType: ResourceZone, ResourceID: "zone_one"},
			{Permission: PermissionZonesRead, Surface: SurfaceAPI, ResourceType: ResourceZone, ResourceID: "zone_two"},
		},
	}
	if !Authorize(principal, PermissionZonesRead, ResourceZone, "zone_one") {
		t.Fatal("web grant did not authorize its selected zone")
	}
	if Authorize(principal, PermissionZonesRead, ResourceZone, "zone_two") {
		t.Fatal("API grant authorized a Web UI request")
	}
	if Authorize(principal, PermissionZonesRead, ResourceZone, "zone_three") {
		t.Fatal("selected-zone grant authorized another zone")
	}
	if Authorize(principal, PermissionZonesCreate, "", "") {
		t.Fatal("zone read grant authorized a global create operation")
	}
}

func TestAuthorizeAllZoneGrantAndAdministratorGrant(t *testing.T) {
	t.Parallel()
	allZones := Principal{Surface: SurfaceAPI, Grants: []Grant{{
		Permission: PermissionZonesExport, Surface: SurfaceAPI,
		ResourceType: ResourceZone, ResourceID: ResourceAll,
	}}}
	if !Authorize(allZones, PermissionZonesExport, ResourceZone, "zone_any") {
		t.Fatal("all-zones grant did not authorize a zone")
	}
	administrator := Principal{Surface: SurfaceWeb, Grants: []Grant{{Permission: PermissionAll, Surface: SurfaceWeb}}}
	if !Authorize(administrator, PermissionZonesDelete, ResourceZone, "zone_any") ||
		!Authorize(administrator, PermissionUsersWrite, "", "") {
		t.Fatal("administrator grant did not authorize all resources")
	}
}
