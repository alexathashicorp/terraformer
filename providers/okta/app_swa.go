// Copyright 2021 The Terraformer Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package okta

import (
	"context"
	"log"

	"github.com/GoogleCloudPlatform/terraformer/terraformutils"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

type AppSWAGenerator struct {
	OktaService
}

func (g AppSWAGenerator) createResources(ctx context.Context, client *okta.Client, appList []*okta.Application) []terraformutils.Resource {
	var resources []terraformutils.Resource
	for _, app := range appList {
		appPolicyId, err := getApplicationPolicy(ctx, client, app)
		if err != nil {
			panic(err)
		}

		r := terraformutils.NewResource(
			app.Id,
			normalizeResourceName(app.Id+"_"+app.Name),
			"okta_app_swa",
			"okta",
			map[string]string{
				"authentication_policy": appPolicyId,
				"skip_users":            "true",
				"skip_groups":           "true",
			},
			[]string{},
			map[string]interface{}{},
		)
		r.IgnoreKeys = append(r.IgnoreKeys, "^groups", "^users")
		groups := g.initSWAGroups(ctx, client, app)
		r.SlowQueryRequired = true
		resources = append(resources, r)
		resources = append(resources, groups...)
	}
	return resources
}

func (g *AppSWAGenerator) InitResources() error {
	ctx, client, e := g.Client()
	if e != nil {
		return e
	}

	apps, err := getSWAApplications(ctx, client)
	if err != nil {
		return err
	}

	g.Resources = g.createResources(ctx, client, apps)
	return nil
}

func getSWAApplications(ctx context.Context, client *okta.Client) ([]*okta.Application, error) {
	signOnMode := "BROWSER_PLUGIN"
	apps, err := getApplications(ctx, client, signOnMode)
	if err != nil {
		return nil, err
	}

	swaApps := []*okta.Application{}
	swaApps = append(swaApps, apps...)

	return swaApps, nil
}

func (g AppSWAGenerator) initSWAGroups(ctx context.Context, client *okta.Client, app *okta.Application) []terraformutils.Resource {
	groupsIDs, err := listApplicationGroupsIDs(ctx, client, app.Id)
	if err != nil {
		log.Println(err)
	}
	var resources []terraformutils.Resource
	for _, groupID := range groupsIDs {
		output, _, _ := client.Group.GetGroup(ctx, groupID)
		groupName := output.Profile.Name
		r := terraformutils.NewResource(
			app.Id,
			normalizeResourceName(app.Id+"_"+app.Label+"__"+groupID+"_"+groupName),
			"okta_app_group_assignment",
			"okta",
			map[string]string{
				"group_id": groupID,
				"app_id":   app.Id,
			},
			[]string{},
			map[string]interface{}{})
		r.SlowQueryRequired = true
		resources = append(resources, r)
	}
	return resources
}

func (g *AppSWAGenerator) PostConvertHook() error {
	for i := range g.Resources {
		g.Resources[i].Item = replaceParams(g.Resources[i].Item)
	}
	return nil
}
