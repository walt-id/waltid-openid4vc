package id.walt.web

import io.github.smiley4.ktorswaggerui.dsl.delete
import io.github.smiley4.ktorswaggerui.dsl.get
import io.github.smiley4.ktorswaggerui.dsl.put
import io.github.smiley4.ktorswaggerui.dsl.route
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonObject

object HelloApi {

    private fun Application.walletRoute(build: Route.() -> Unit) {
        routing {
         //   authenticate("authenticated") {
                route("api/xyz", {
                    tags = listOf("wallet")
                }) {
                    build.invoke(this)
                }
            }
        //}
    }

    fun Application.helloApi() = walletRoute {
        route("hello") {
            get({
                summary = "List users"
                response {
                    HttpStatusCode.OK to {
                        description = "Array of users"
                        body<List<JsonObject>>()
                    }
                }
            }) {
                context.respond("")
            }

            route("{id}") {
                get({
                    summary = "Load a user"
                }) {
                    TODO()
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
