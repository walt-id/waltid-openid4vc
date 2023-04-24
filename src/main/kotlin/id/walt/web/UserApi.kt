package id.walt.web

import id.walt.db.models.Users
import io.github.smiley4.ktorswaggerui.dsl.delete
import io.github.smiley4.ktorswaggerui.dsl.get
import io.github.smiley4.ktorswaggerui.dsl.put
import io.github.smiley4.ktorswaggerui.dsl.route
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonObject
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.selectAll

object UserApi {

    private fun Application.walletRoute(build: Route.() -> Unit) {
        routing {
         //   authenticate("authenticated") {
                route("api/xyz", {
                    tags = listOf("user")
                }) {
                    build.invoke(this)
                }
            }
        //}
    }

    fun Application.helloApi() = walletRoute {
        route("user") {
            get({
                summary = "List users"
                response {
                    HttpStatusCode.OK to {
                        description = "Array of users"
                        body<List<JsonObject>>()
                    }
                }
            }) {
                context.respond(Users.selectAll())
            }

            route("{id}") {
                get({
                    summary = "Load a user"
                }) {
                    val id = context.parameters.get("id")
                }
            }

            put({
                summary = "Store user"
            }) {
                TODO()
            }

            route("{id}") {
                delete({
                    summary = "Delete a user"
                }) {
                    TODO()
                }
            }
        }
    }
}
